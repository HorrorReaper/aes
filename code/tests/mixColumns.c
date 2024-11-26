#include "../src/aes.h"
#include <stdio.h>

int main() {
    uint8_t input[16] = {
        0x63, 0x7b, 0xc0, 0xd2,
        0x7b, 0x76, 0xd2, 0x7c,
        0x76, 0x75, 0x7c, 0xc5,
        0x75, 0x63, 0xc5, 0xc0
    };

    uint8_t expected_result[16] = {
        0x59, 0x1c, 0xee, 0xa1,
        0xc2, 0x86, 0x36, 0xd1,
        0xca, 0xdd, 0xaf, 0x02,
        0x4a, 0x27, 0xdc, 0xa2
    };

    mixColumns(input);

    for(int i = 0; i < 16; i++) {
        if (input[i] != expected_result[i]) {
            printf("Error at index %d\n", i);
            printf("Expected: %x\n", expected_result[i]);
            printf("Got: %x\n", input[i]);
            return 1;
        }
    }

    return 0;
}