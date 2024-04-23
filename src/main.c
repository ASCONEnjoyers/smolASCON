#include <stdio.h>
#include <stdlib.h>
#include "headers/ascon128.h"

int main()
{

    char buf[500];

    while (1)
    {
        scanf("%s", buf);
        uint64_t *K = (uint64_t *) calloc(2, sizeof(uint64_t));
        K[0] = 7822;
        uint64_t *N = (uint64_t *) calloc(2, sizeof(uint64_t));
        N[1]=12;
        uint64_t *state = generateFirstState(K, N);
        for(int i = 0; i < 5; i++)
        {
            printf("%lx\n", state[i]);
        }
    }

    return 0;
}