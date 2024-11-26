#include "../src/aes.h"
#include <stdio.h>

int main()
{
    uint8_t state[16] = {
        0x00, 0x00, 0x01, 0x01,
        0x03, 0x03, 0x07, 0x07,
        0x0f, 0x0f, 0x1f, 0x1f,
        0x3f, 0x3f, 0x7f, 0x7f
    };
    uint8_t desired_result[16] = {
        0x63, 0x63, 0x7c, 0x7c,
        0x7b, 0x7b, 0xc5, 0xc5,
        0x76, 0x76, 0xc0, 0xc0,
        0x75, 0x75, 0xd2, 0xd2
    };

    subBytes(state);

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