#include "aes.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

// S-Box und Inverse S-Box

static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16 };

static const uint8_t rsbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
    0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
    0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
    0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
    0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d };

unsigned int numRounds(unsigned int keySize) {
    if (keySize == 128) {
        return 10;
    }
    else if (keySize == 192) {
        return 12;
    }
    else if (keySize == 256) {
        return 14;
    }

    return -1;
}//Test bestanden

unsigned int numKeyWords(unsigned int keySize) {
    // Gibt die Anzahl der Schlüsselwörter zur Schlüssellänge in Bit zurück, bei ungültiger Schlüssellänge wird -1 zurückgegeben
    if (keySize == 128)
        return 4;
    else if (keySize == 192)
        return 6;
    else if (keySize == 256)
        return 8;
    return -1;
}//Test bestanden

uint8_t getSBoxValue(uint8_t num) {
    return sbox[num];
}

uint8_t getSBoxInvert(uint8_t num) {
    // Gibt die Ergebnisse der inversen SBox für die Eingabe zurück. Die inverse S-Box ist in der Datei aes.c bereits bereitgestellt.
    return rsbox[num];
}


uint8_t rc(uint8_t num) {
    // Gibt den Rundenkonstantenwert rc für die Runde zurück.
    uint8_t j = 0x01;
    for (int i = 0; i < (num - 1); i++) {
        //j <<= 1;
        j = multiplyt2(j);
    }
    return j;
}
//bis hierher hat alles bestanden
void keyExpansion(uint8_t* key, uint8_t* roundKeys, unsigned int keySize) {
    uint8_t * expandedKey2 = NULL;
    // Berechnung der Parameter
    unsigned int keyWords = numKeyWords(keySize); // Anzahl Words im Schlüssel
    unsigned int rounds = numRounds(keySize);    // Anzahl der Runden
    printf("keyWords: %u, rounds: %u\n", keyWords, rounds);

    int expandedKeySize = 4 * (rounds + 1); // Correct size calculation // Anzahl Wörter im erweiterten Schlüssel
    printf("expandedKeySize: %u, requested size: %zu bytes\n", expandedKeySize, expandedKeySize * 4);

    // Speicher für den erweiterten Schlüssel
    //expandedKey = (uint8_t*)malloc(expandedKeySize * 4); //hier scheint der Fehler zu liegen: -		expandedKey	0xfffffffffb1fa110 <Fehler beim Lesen der Zeichen der Zeichenfolge.>	unsigned char *
    expandedKey2 = (uint8_t*)calloc(expandedKeySize * 4, sizeof(uint8_t));
    printf("expandedKey: %p\n", expandedKey2);

    if (expandedKey2 == NULL || key == NULL || roundKeys == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }

    // Initialisierung
    memcpy(expandedKey2, key, keyWords * 4);
    uint8_t temp[4];

    uint8_t rcon = 0x01;

    // Schlüsselerweiterung
    for (unsigned int i = keyWords; i < expandedKeySize; i++) {
        memcpy(temp, expandedKey2 + (i - 1) * 4, 4);

        if (i % keyWords == 0) {
            // RotWord
            uint8_t firstByte = temp[0];
            temp[0] = getSBoxValue(temp[1]);
            temp[1] = getSBoxValue(temp[2]);
            temp[2] = getSBoxValue(temp[3]);
            temp[3] = getSBoxValue(firstByte);

            // Rcon XOR
            rcon = rc(i / keyWords);
            temp[0] ^= rcon;
        }
        else if (keyWords > 6 && i % keyWords == 4) {
            // SubWord
            for (unsigned int j = 0; j < 4; j++) {
                temp[j] = getSBoxValue(temp[j]);
            }
        }

        // Berechnung des erweiterten Schlüssels
        for (unsigned int j = 0; j < 4; j++) {
            expandedKey2[i * 4 + j] = expandedKey2[(i - keyWords) * 4 + j] ^ temp[j];
        }
    }

    // Kopiere den erweiterten Schlüssel in roundKeys
    memcpy(roundKeys, expandedKey2, expandedKeySize * 4);
    free(expandedKey2);
}
//hat funktioniert

void getRoundKey(uint8_t* roundKeys, uint8_t* roundKey, uint8_t round) {
    // Gibt den Rundenschlüssel für die Runde round zurück.
    memcpy(roundKey, roundKeys + round * 16, 16);

}//hat funktioniert

void addRoundKey(uint8_t* state, uint8_t* roundKey) {
    // Addiert den Rundenschlüssel roundKey zum Zustand state.
    for (int i = 0; i < 16; i++) {
        state[i] ^= roundKey[i];//XOR 
    }
}//hat funktioniert

void subBytes(uint8_t* state) {
    // Substituiert die Bytes im Zustand state mit der S-Box.
    for (int i = 0; i < 16; i++) {
        state[i] = getSBoxValue(state[i]);
    }

}//hat funktioniert

void shiftRows(uint8_t* state) {
    // Verschiebt die Zeilen im Zustand state.
    uint8_t temp[16];
    memcpy(temp, state, 16);
    state[1] = temp[5];
    state[5] = temp[9];
    state[9] = temp[13];
    state[13] = temp[1];

    state[2] = temp[10];
    state[6] = temp[14];
    state[10] = temp[2];
    state[14] = temp[6];

    state[3] = temp[15];
    state[7] = temp[3];
    state[11] = temp[7];
    state[15] = temp[11];
}//hat funktioniert

void multiply2(uint8_t* state) {
    // Multipliziert die Spalten im Zustand state mit zwei.
    // Beachten Sie die spezielle Addition in der Galois-Field-Arithmetik.
    // Für die Multiplikation mit zwei ist der Ausgangswert um eins nach links zu shiften, und anschließend mit dem Produkt von 0x1b und dem größten Bit des Ausgangswertes zu XORen, wenn das größte Bit des Ausgangswertes 1 ist.
    for (int i = 0; i < 16; i++) {
        uint8_t temp = state[i];
        state[i] <<= 1;
        if (temp & 0x80) {
            state[i] ^= 0x1b;
        }
    }
}// hat funktioniert


void multiply3(uint8_t* state) {
    // Multipliziert die Spalten im Zustand state mit drei.
    // Beachten Sie die spezielle Addition in der Galois-Field-Arithmetik.
    // Nutzen Sie die bekannten Multiplikation mit zwei und Addieren Sie anschließend einmal den Ausgangswert durch Verwendung von xor auf.
    uint8_t temp[16];
    memcpy(temp, state, 16);
    multiply2(state);
    for (int i = 0; i < 16; i++) {
        state[i] ^= temp[i];
    }
}//hat funktioniert
uint8_t multiplyt2(uint8_t state) {
    // Multiplies the columns in the state with two.
    // Take note of the special addition in Galois Field arithmetic.
    // To multiply by two, the input value is left-shifted by one, and then XORed with 0x1b if the most significant bit of the input value is 1.
    uint8_t result = state << 1;
    if (state & 0x80) {
        result ^= 0x1b;
    }
    return result;
}

uint8_t multiplyt3(uint8_t state) {
    // Multiplies the columns in the state with three.
    // Take note of the special addition in Galois Field arithmetic.
    // Use the known multiplication by two and then XOR the output once using the input value.
    return multiplyt2(state) ^ state;
}

void mixColumns(uint8_t* state) {
    // Führt die Berechnug von mixColumns auf dem Zustand state durch.
    uint8_t temp[16];
    memcpy(temp, state, 16);
    state[0] = multiplyt2(temp[0]) ^ multiplyt3(temp[1]) ^ temp[2] ^ temp[3];
    state[1] = temp[0] ^ multiplyt2(temp[1]) ^ multiplyt3(temp[2]) ^ temp[3];
    state[2] = temp[0] ^ temp[1] ^ multiplyt2(temp[2]) ^ multiplyt3(temp[3]);
    state[3] = multiplyt3(temp[0]) ^ temp[1] ^ temp[2] ^ multiplyt2(temp[3]);

    state[4] = multiplyt2(temp[4]) ^ multiplyt3(temp[5]) ^ temp[6] ^ temp[7];
    state[5] = temp[4] ^ multiplyt2(temp[5]) ^ multiplyt3(temp[6]) ^ temp[7];
    state[6] = temp[4] ^ temp[5] ^ multiplyt2(temp[6]) ^ multiplyt3(temp[7]);
    state[7] = multiplyt3(temp[4]) ^ temp[5] ^ temp[6] ^ multiplyt2(temp[7]);

    state[8] = multiplyt2(temp[8]) ^ multiplyt3(temp[9]) ^ temp[10] ^ temp[11];
    state[9] = temp[8] ^ multiplyt2(temp[9]) ^ multiplyt3(temp[10]) ^ temp[11];
    state[10] = temp[8] ^ temp[9] ^ multiplyt2(temp[10]) ^ multiplyt3(temp[11]);
    state[11] = multiplyt3(temp[8]) ^ temp[9] ^ temp[10] ^ multiplyt2(temp[11]);

    state[12] = multiplyt2(temp[12]) ^ multiplyt3(temp[13]) ^ temp[14] ^ temp[15];
    state[13] = temp[12] ^ multiplyt2(temp[13]) ^ multiplyt3(temp[14]) ^ temp[15];
    state[14] = temp[12] ^ temp[13] ^ multiplyt2(temp[14]) ^ multiplyt3(temp[15]);
    state[15] = multiplyt3(temp[12]) ^ temp[13] ^ temp[14] ^ multiplyt2(temp[15]);
}//hat funktioniert
uint8_t multiplyt9(uint8_t value) {
    return multiplyt2(multiplyt2(multiplyt2(value))) ^ value; // 9 = 2^3 + 1
}

uint8_t multiplytB(uint8_t value) {
    return multiplyt9(value) ^ multiplyt2(value); // B = 2^3 + 2 + 1
}

uint8_t multiplytD(uint8_t value) {
    return multiplyt9(value) ^ multiplyt2(multiplyt2(value)); // D = 2^3 + 2^2 + 1
}

uint8_t multiplytE(uint8_t value) {
    return multiplyt2(multiplyt2(multiplyt2(value))) ^ multiplyt2(multiplyt2(value)) ^ multiplyt2(value); // E = 2^3 + 2^2 + 2
}

void invMixColumns(uint8_t* state) {
    // Umkehrung von mixColumns. Entnehmen Sie die MixColumns-Matrix aus dem bereitgestellten Buch.
    // Für die Multiplikation mit 9, 11, 13 und 14 können Sie die Funktion Multiply verwenden, die in der Datei aes.c bereitgestellt ist.
    uint8_t temp[16];
    memcpy(temp, state, 16);

    for (int i = 0; i < 4; i++) {
        state[i * 4 + 0] = multiplytE(temp[i * 4 + 0]) ^ multiplytB(temp[i * 4 + 1]) ^ multiplytD(temp[i * 4 + 2]) ^ multiplyt9(temp[i * 4 + 3]);
        state[i * 4 + 1] = multiplyt9(temp[i * 4 + 0]) ^ multiplytE(temp[i * 4 + 1]) ^ multiplytB(temp[i * 4 + 2]) ^ multiplytD(temp[i * 4 + 3]);
        state[i * 4 + 2] = multiplytD(temp[i * 4 + 0]) ^ multiplyt9(temp[i * 4 + 1]) ^ multiplytE(temp[i * 4 + 2]) ^ multiplytB(temp[i * 4 + 3]);
        state[i * 4 + 3] = multiplytB(temp[i * 4 + 0]) ^ multiplytD(temp[i * 4 + 1]) ^ multiplyt9(temp[i * 4 + 2]) ^ multiplytE(temp[i * 4 + 3]);
    }
}//hat funktioniert

void printBlock(uint8_t* block) {
    for (int i = 0; i < 16; i++) {
        printf("%02x ", block[i]);
        if (i % 4 == 3) {
            printf("\n");
        }
    }
}

void encrypt(uint8_t* block, uint8_t* roundKeys, unsigned int rounds) {
    // Verschlüsselt den Block mit den expandierten Schlüsseln roundKeys und der Anzahl der Runden rounds.
    addRoundKey(block, roundKeys);
    for (int i = 1; i < rounds; i++) {
        subBytes(block);
        shiftRows(block);
        mixColumns(block);
        addRoundKey(block, roundKeys + i * 16);
    }
    subBytes(block);
    shiftRows(block);
    addRoundKey(block, roundKeys + rounds * 16);
}//hat funktioniert

void invSubBytes(uint8_t* state) {
    // Umkehrung von subBytes. Nutzen Sie die inverse S-Box, die in der Datei aes.c bereitgestellt ist.
    for (int i = 0; i < 16; i++) {
        state[i] = getSBoxInvert(state[i]);
    }
}//hat funktioniert

void invShiftRows(uint8_t* state) {
    // Umkehrung von shiftRows.
    uint8_t temp[16];
    memcpy(temp, state, 16);


    state[5] = temp[1];
    state[9] = temp[5];
    state[13] = temp[9];
    state[1] = temp[13];

    state[10] = temp[2];
    state[14] = temp[6];
    state[2] = temp[10];
    state[6] = temp[14];

    state[15] = temp[3];
    state[3] = temp[7];
    state[7] = temp[11];
    state[11] = temp[15];
}//hat funktioniert

void decrypt(uint8_t* block, uint8_t* roundKeys, unsigned int rounds) {
    // Entschlüsselt den Block mit den expandierten Schlüsseln roundKeys und der Anzahl der Runden rounds.
    addRoundKey(block, roundKeys + rounds * 16);
    invShiftRows(block);
    invSubBytes(block);
    for (int i = rounds - 1; i > 0; i--) {
        addRoundKey(block, roundKeys + i * 16);
        invMixColumns(block);
        invShiftRows(block);
        invSubBytes(block);
    }
    addRoundKey(block, roundKeys);
}//hat funktioniert

void ecb_encrypt(uint8_t* content, uint8_t* key, unsigned int keySize, size_t length) {
    // Verschlüsselt den Inhalt mit dem Schlüssel key und der Schlüssellänge keySize unter Verwendung des ECB-Verfahrens.
    unsigned int rounds = numRounds(keySize);
    unsigned int expandedKeySize = 4 * (rounds + 1);
    uint8_t* roundKeys = (uint8_t*)malloc(expandedKeySize * 4 * sizeof(uint8_t));
    if (roundKeys == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    keyExpansion(key, roundKeys, keySize);

    for (size_t i = 0; i < length; i += 16) {
        encrypt(content + i, roundKeys, rounds);
    }

    free(roundKeys);
}
//hat funktioniert

void ecb_decrypt(uint8_t* content, uint8_t* key, unsigned int keySize, size_t length) {
    // Entschlüsselt den Inhalt mit dem Schlüssel key und der Schlüssellänge keySize unter Verwendung des ECB-Verfahrens.
    unsigned int rounds = numRounds(keySize);
    unsigned int expandedKeySize = 4 * (rounds + 1);
    uint8_t* roundKeys = (uint8_t*)malloc(expandedKeySize * 4 * sizeof(uint8_t));
    if (roundKeys == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    keyExpansion(key, roundKeys, keySize);

    for (size_t i = 0; i < length; i += 16) {
        decrypt(content + i, roundKeys, rounds);
    }

    free(roundKeys);
}
//hat funktioniert
void cbc_encrypt(uint8_t* content, uint8_t* key, unsigned int keySize, uint8_t* iv, size_t length) {
    // Verschlüsselt den Inhalt mit dem Schlüssel key und der Schlüssellänge keySize unter Verwendung des CBC-Verfahrens mit dem Initialisierungsvektor iv.
    unsigned int rounds = numRounds(keySize);
    unsigned int expandedKeySize = 4 * (rounds + 1);
    uint8_t* roundKeys = (uint8_t*)malloc(expandedKeySize * 4 * sizeof(uint8_t));
    if (roundKeys == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    keyExpansion(key, roundKeys, keySize);

    uint8_t* ivCopy = (uint8_t*)malloc(16 * sizeof(uint8_t));
    if (ivCopy == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    memcpy(ivCopy, iv, 16);

    for (size_t i = 0; i < length; i += 16) {
        for (int j = 0; j < 16; j++) {
            content[i + j] ^= ivCopy[j];
        }
        encrypt(content + i, roundKeys, rounds);
        memcpy(ivCopy, content + i, 16);
    }

    free(roundKeys);
    free(ivCopy);
}
//hat funktioniert

void cbc_decrypt(uint8_t* content, uint8_t* key, unsigned int keySize, uint8_t* iv, size_t length) {
    // Entschlüsselt den Inhalt mit dem Schlüssel key und der Schlüssellänge keySize unter Verwendung des CBC-Verfahrens mit dem Initialisierungsvektor iv.
    unsigned int rounds = numRounds(keySize);
    unsigned int expandedKeySize = 4 * (rounds + 1);
    uint8_t* roundKeys = (uint8_t*)malloc(expandedKeySize * 4 * sizeof(uint8_t));
    if (roundKeys == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    keyExpansion(key, roundKeys, keySize);

    uint8_t* ivCopy = (uint8_t*)malloc(16 * sizeof(uint8_t));
    if (ivCopy == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    memcpy(ivCopy, iv, 16);

    for (size_t i = 0; i < length; i += 16) {
        uint8_t* temp = (uint8_t*)malloc(16 * sizeof(uint8_t));
        if (temp == NULL) {
            fprintf(stderr, "Memory allocation failed\n");
            exit(1);
        }
        memcpy(temp, content + i, 16);
        decrypt(content + i, roundKeys, rounds);
        for (int j = 0; j < 16; j++) {
            content[i + j] ^= ivCopy[j];
        }
        memcpy(ivCopy, temp, 16);
        free(temp);
    }

    free(roundKeys);
    free(ivCopy);
}
//hat funktioniert