#include <stdio.h>
#include "headers/ascon128.h"

int main()
{

    char plaintext[500];
    char associated[500] = {0};

    char key[17] = "sbiriguldaantani";
    char nonce[16] = {0};

    while (1)
    {

        scanf("%s", plaintext);
        scanf("%s", associated);

        char *ciphertext = encrypt(plaintext, associated, key, nonce);
        printf("Plaintext> %s\n", plaintext);
        printf("Associated> %s\n", associated);
        printf("Ciphertext> %s\n", ciphertext);

        char *m = decrypt(ciphertext, associated, key, nonce);

        printf("Decrypted plaintext> %s\n\n", m);
        printf("Nonce used> %32x\n\n", *nonce);
        *nonce += 1;
    }

    return 0;
}