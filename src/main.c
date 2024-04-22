#include <stdio.h>
#include "headers/ascon128.h"

int main()
{

    char buf[500];

    while (1)
    {
        scanf("%s", buf);
        uint64_t *iv = generateIV(64, 12, 6);
        printf("%lx", *iv);
    }

    return 0;
}