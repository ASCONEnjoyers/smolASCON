#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "headers/ascon128.h"

int main()
{

    char plaintext[500] = "antani";
    char associated[500] = {0};

    char key[17] = "antaniantani1234";
    char nonce[17] = "antaniantani1234";

    while (1)
    {

        scanf("%s", plaintext);
        // scanf("%s", associated);

        ascon_t *ascon = encrypt(plaintext, associated, key, nonce);

        printf("Plaintext> %s\n", plaintext);
        printf("Associated> %s\n", associated);
        printf("Ciphertext> %s\n", ascon->ciphertext);
        printf("Tag: %s\n", ascon->tag);

        char *m = decrypt(ascon->ciphertext, associated, key, nonce);

        printf("Decrypted plaintext> %s\n\n", m);
        printf("decrypted length: %ld\n", strlen(m));
        printf("Nonce used> %lx%lx\n\n", *((uint64_t *)nonce), *((uint64_t *)nonce + 1));

        incrementNonce(nonce);
    }

    /*int check = 1, counter = 0;
    while(check){
        ascon_t *ascon = encrypt(plaintext, associated, key, nonce);
        //printf("Ciphertext> %s\n", ascon->ciphertext);
        char *m = decrypt(ascon->ciphertext, associated, key, nonce);
        //printf("Decrypted plaintext> %s\n\n", m);
        printf("Ciphertext> %s\n", ascon->ciphertext);
        printf("Nonce used> %lx%lx\n\n", *((uint64_t *)nonce), *((uint64_t *)nonce + 1));
        incrementNonce(nonce);
        printf("Counter: %d\n", counter++);
        if(strcmp(plaintext, m)){
            check = 0;
            //printf("Counter: %d\n", counter++);
            printf("Ciphertext> %s\n", ascon->ciphertext);
            printf("Decrypted plaintext> %s\n\n", m);
        }
    }*/

    return 0;
}