#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

int sign_block(const char* data, const char* private_key_path, unsigned char* signature, size_t * sig_len);

typedef struct Block {
    int voter_id;
    char previous_hash[65];
    char hash[65];
    char data[256];
    time_t timestamp;
    unsigned char signature[256]; 
    struct Block* next;
} Block;

void sha256(const char* str, unsigned char* hash) {
    SHA256((unsigned char*)str, strlen(str), hash);
}

void calculate_hash(Block* block) {
    char str[1024];
    snprintf(str, sizeof(str), "%d%ld%s%s", block->voter_id, block->timestamp, block->previous_hash, block->data);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    sha256(str, hash);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&block->hash[i * 2], "%02x", hash[i]);
    }
    block->hash[64] = '\0';
}

Block* create_block(int voter_id, const char* previous_hash, const char* data, const char* private_key_path) {
    Block* new_block = (Block*)malloc(sizeof(Block));
    if (!new_block) {
        printf("Failed to allocate memory for Voter Id: %d\n",voter_id);
        perror("Error: ");
        exit(EXIT_FAILURE);
    }
    new_block->voter_id = voter_id;
    strcpy(new_block->data, data);
    strcpy(new_block->previous_hash, previous_hash);
    new_block->timestamp = time(NULL);
    new_block->next = NULL;
    calculate_hash(new_block);

    size_t sig_len;
    if (sign_block(data, private_key_path, new_block->signature, &sig_len) != 0) {
        fprintf(stderr, "Failed to sign block\n");
        free(new_block);
        exit(EXIT_FAILURE);
    }

    return new_block;
}

void add_block(Block** head, int voter_id, const char* data, const char* private_key_path) {
    if (*head == NULL) {
        *head = create_block(voter_id, "0", data, private_key_path);
        return;
    }

    Block* current = *head;
    while (current->next != NULL) {
        current = current->next;
    }

    current->next = create_block(voter_id, current->hash, data, private_key_path);
}

void print_blockchain(Block* head) {
    Block* current = head;
    while (current != NULL) {
        printf("Voter Id: %d\n", current->voter_id);
        printf("Previous Hash: %s\n", current->previous_hash);
        printf("Hash: %s\n", current->hash);
        printf("Timestamp: %ld\n", current->timestamp);
        printf("Data: %s\n", current->data);
        printf("Signature: ");
        for (int i = 0; i < sizeof(current->signature); i++) {
            printf("%02x", current->signature[i]);
        }
        printf("\n\n");

        current = current->next;
    }
}

int sign_block(const char* data, const char* private_key_path, unsigned char* signature, size_t * sig_len) {
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    BIO *keybio = NULL;
    keybio = BIO_new(BIO_s_file());
    if (BIO_read_filename(keybio, private_key_path) <= 0) {
        fprintf(stderr, "Error reading private key file\n");
        BIO_free(keybio);
        return -1;
    }
    pkey = PEM_read_bio_PrivateKey(keybio, &pkey, NULL, NULL);

    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(pkey);
        BIO_free(keybio);
        return -1;
    }

    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        BIO_free(keybio);

        return -1;
    }

    if (EVP_DigestSignUpdate(mdctx, data, strlen(data)) != 1) {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        BIO_free(keybio);

        return -1;
    }

    if (EVP_DigestSignFinal(mdctx, signature, sig_len) != 1) {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        BIO_free(keybio);

        return -1;
    }

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    BIO_free(keybio);

    return 0;
}

int verify_block(const char* data, const unsigned char* signature, size_t sig_len, const char* public_key_path) {
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    BIO *keybio = NULL;
    keybio = BIO_new(BIO_s_file());

     if (BIO_read_filename(keybio, public_key_path) <= 0) {
        fprintf(stderr, "Error reading Public key file\n");
        BIO_free(keybio);
        return -1;
    }

    pkey = PEM_read_bio_PUBKEY(keybio, &pkey, NULL, NULL);
    

    if (!pkey) {
        ERR_print_errors_fp(stderr);
        BIO_free(keybio);

        return -1;
    }

    mdctx = EVP_MD_CTX_new();

    if (!mdctx) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(pkey);
        BIO_free(keybio);

        return -1;
    }

    if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        BIO_free(keybio);

        return -1;
    }


    if (EVP_DigestVerifyUpdate(mdctx, data, strlen(data)) != 1) {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        BIO_free(keybio);

        return -1;
    }
    int verified=EVP_DigestVerifyFinal(mdctx, signature, sig_len);
    if (verified!=1 && verified !=0) {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        BIO_free(keybio);

        return -1;
    }


    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    BIO_free(keybio);

    return verified;
}

int verify_blockchain(Block* head, const char* public_key_path) {
    Block* current = head;
    while (current != NULL) {
        char str[1024];
        snprintf(str, sizeof(str), "%d%ld%s%s", current->voter_id, current->timestamp, current->previous_hash, current->data);
        unsigned char computed_hash[SHA256_DIGEST_LENGTH];
        sha256(str, computed_hash);

        char computed_hash_str[65];
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            sprintf(&computed_hash_str[i * 2], "%02x", computed_hash[i]);
        }
        computed_hash_str[64] = '\0';

        if (strcmp(current->hash, computed_hash_str) != 0) {
            printf("Hash verification failed for Voter Id: %d\n", current->voter_id);
            return -1;
        }

        size_t sig_len = sizeof(current->signature);
        if (verify_block(current->data, current->signature, sig_len, public_key_path)==0) {
            printf("Signature verification failed for Voter Id %d\n", current->voter_id);
            return -1;
        }

        if (current->voter_id != 1) {
            Block* prev = head;
            while (prev->next != current) {
                prev = prev->next;
            }

            if (strcmp(current->previous_hash, prev->hash) != 0) {
                printf("Previous hash verification failed for Voter Id %d\n", current->voter_id);
                return -1;
            }
        }

        current = current->next;
    }

    return 0;
}

int main() {
    const char* private_key_path = "private_key.pem";
    const char* public_key_path = "public_key.pem";

    Block* blockchain = NULL;

    add_block(&blockchain, 1, "Vote to A", private_key_path);
    add_block(&blockchain, 2, "Vote to B", private_key_path);
    add_block(&blockchain, 3, "Vote to A", private_key_path);

    print_blockchain(blockchain);

    Block* block_to_update = blockchain->next;
    if(verify_blockchain(blockchain, public_key_path)==0){
        printf("Blockchain is valid\n");
    }


    Block* next;
    Block* current = blockchain;
    while (current != NULL) {
        next = current->next;
        free(current);
        current = next;
    }

    return 0;
}
