#define KEY_SIZE 128
#define NONCE_SIZE 64
#define BLOCK_SIZE 64
#define A 12
#define B 6

char *encrypt(char *plaintext, char *associated, char *key, char *nonce);
char *decrypt(char *ciphertext, char *associated, char *key, char *nonce);