#include <stdio.h>
#include <stdlib.h>
#include "headers/ascon128.h"

int main()
{

    char plaintext[500];
    char associated[500];

    while (1)
    {
        scanf("%s", plaintext);
        scanf("%s", associated);
        /*uint64_t *K = (uint64_t *)calloc(2, sizeof(uint64_t));
        K[0] = 0xf000000000000000;
        K[1] = 0xef000000000000f1;
        uint64_t *N = (uint64_t *)calloc(2, sizeof(uint64_t));
        N[0] = 0xf000000000000000;
        N[1] = 0xf000000000000000;
        uint64_t *state = generateEntranceState(K, N);
        for (int i = 0; i < 5; i++)
        {
            printf("%16lx\n", state[i]);
        }
        printf("\n");

        uint64_t *newState = doPermutation(state, 0, 0);
        for (int i = 0; i < 5; i++)
        {
            printf("%16lx\n", newState[i]);
        }
        printf("\n");*/

        splitDataIn64bitBlock(plaintext);

        return 0;
    }
}