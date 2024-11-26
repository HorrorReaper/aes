#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

// Gibt die Anzahl der Runden zur Schlüssellänge in Bit zurück, bei ungültiger Schlüssellänge wird -1 zurückgegeben
unsigned int numRounds(unsigned int keySize);

// Gibt die Anzahl der Schlüsselwörter zur Schlüssellänge in Bit zurück, bei ungültiger Schlüssellänge wird -1 zurückgegeben
unsigned int numKeyWords(unsigned int keySize);

// Gibt die Ergebnisse der SBox für die Eingabe zurück. Die S-Box ist in der Datei aes.c bereits bereitgestellt.
uint8_t getSBoxValue(uint8_t* num);


// Gibt die Ergebnisse der inversen SBox für die Eingabe zurück. Die inverse S-Box ist in der Datei aes.c bereits bereitgestellt.
uint8_t getSBoxInvert(uint8_t num);

// Gibt den Rundenkonstantenwert rc für die Runde zurück.
uint8_t rc(uint8_t num);

// Führt die Schlüsselerweiterung durch und speichert die Rundenschlüssel in roundKeys.
void keyExpansion(uint8_t* key, uint8_t* roundKeys, unsigned int keySize);

// Gibt den Rundenschlüssel für die Runde round zurück.
void getRoundKey(uint8_t* roundKeys, uint8_t* roundKey, uint8_t round);

// Addiert den Rundenschlüssel roundKey zum Zustand state.
void addRoundKey(uint8_t* state, uint8_t* roundKey);

// Substituiert die Bytes im Zustand state mit der S-Box.
void subBytes(uint8_t* state);

// Verschiebt die Zeilen im Zustand state.
void shiftRows(uint8_t* state);

// Multipliziert die Spalten im Zustand state mit zwei.
// Beachten Sie die spezielle Addition in der Galois-Field-Arithmetik.
// Für die Multiplikation mit zwei ist der Ausgangswert um eins nach links zu shiften, und anschließend mit dem Produkt von 0x1b und dem größten Bit des Ausgangswertes zu XORen, wenn das größte Bit des Ausgangswertes 1 ist.
void multiply2(uint8_t* state);

// Multipliziert die Spalten im Zustand state mit drei.
// Beachten Sie die spezielle Addition in der Galois-Field-Arithmetik.
// Nutzen Sie die bekannten Multiplikation mit zwei und Addieren Sie anschließend einmal den Ausgangswert durch Verwendung von xor auf.
void multiply3(uint8_t* state);

uint8_t multiplyt2(uint8_t state);

// Führt die Berechnug von mixColumns auf dem Zustand state durch.
void mixColumns(uint8_t* state);

// Verschlüsselt den Block mit den expandierten Schlüssern roundKeys und der Anzahl der Runden rounds.
void encrypt(uint8_t* block, uint8_t* roundKeys, unsigned int rounds);

// Umkehrung von mixColumns. Entnehmen Sie die MixColumns-Matrix aus dem bereitgestellten Buch. 
// Für die Multiplikation mit 9, 11, 13 und 14 können Sie die Funktion Multiply verwenden, die in der Datei aes.c bereitgestellt ist.
void invMixColumns(uint8_t* state);

// Umkehrung von subBytes. Nutzen Sie die inverse S-Box, die in der Datei aes.c bereitgestellt ist.
void invSubBytes(uint8_t* state);

// Umkehrung von shiftRows.
void invShiftRows(uint8_t* state);

// Entschlüsselt den Block mit den expandierten Schlüsseln roundKeys und der Anzahl der Runden rounds.
void decrypt(uint8_t* block, uint8_t* roundKeys, unsigned int rounds);

// Verschlüsselt den Inhalt mit dem Schlüssel key und der Schlüssellänge keySize unter Verwendung des ECB-Verfahrens.
void ecb_encrypt(uint8_t* content, uint8_t* key, unsigned int keySize, size_t length);

// Entschlüsselt den Inhalt mit dem Schlüssel key und der Schlüssellänge keySize unter Verwendung des ECB-Verfahrens.
void ecb_decrypt(uint8_t* content, uint8_t* key, unsigned int keySize, size_t length);

// Verschlüsselt den Inhalt mit dem Schlüssel key und der Schlüssellänge keySize unter Verwendung des CBC-Verfahrens mit dem Initialisierungsvektor iv.
void cbc_encrypt(uint8_t* content, uint8_t* key, unsigned int keySize, uint8_t* iv, size_t length);

// Entschlüsselt den Inhalt mit dem Schlüssel key und der Schlüssellänge keySize unter Verwendung des CBC-Verfahrens mit dem Initialisierungsvektor iv.
void cbc_decrypt(uint8_t* content, uint8_t* key, unsigned int keySize, uint8_t* iv, size_t length);