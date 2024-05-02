#define KEY_SIZE 128
#define NONCE_SIZE 128
#define BLOCK_SIZE 64
#define A 12
#define B 6

typedef struct {
    uint64_t *ciphertext;
    uint64_t *tag;
    uint16_t originalLength;
} ascon_t;

ascon_t *encrypt(char *plaintext, char *associated, char *key, char *nonce);
char *decrypt(ascon_t *ascon, char *associated, char *key, char *nonce);
char *getPrintableText(uint64_t *blocks, uint16_t length);
void incrementNonce(char *nonce);