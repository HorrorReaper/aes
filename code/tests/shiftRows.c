#include "../src/aes.h"
#include <stdio.h>

int main()
{
    uint8_t state[16] = {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f
    };
    uint8_t desired_result[16] = {
        0x00, 0x05, 0x0a, 0x0f,
        0x04, 0x09, 0x0e, 0x03,
        0x08, 0x0d, 0x02, 0x07,
        0x0c, 0x01, 0x06, 0x0b
    };

    shiftRows(state);

    for(int i = 0; i < 16; i++)
    {
        if (state[i] != desired_result[i])
        {
            printf("Error at index %d\n", i);
            printf("Expected: %x\n", desired_result[i]);
            printf("Got: %x\n", state[i]);
            return 1;
        }
    }

    return 0;
}