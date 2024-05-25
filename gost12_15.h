#ifndef _GOST_12_15_H_
#define _GOST_12_15_H_

#include <iostream>
#include <vector>
#include <map>
#include <utility>
#include <QThread>
#include <bitset>

using std::cout;
using std::endl;
using std::vector;
using std::bitset;
using std::map;
using std::pair;

class gost12_15
{
public:

    void setKey(const char *key);
    void setKey_HEX(const char *key);
    void setSync(const char *_sync);
    void setSync_HEX(const char *_sync);
    void clearKey();
    void clearSync();
    void encrypt(uint8_t* encryptedBlock, uint8_t *block);
    void decrypt(uint8_t* block, uint8_t* encryptedBlock);
    bool isKeySetted();
    bool isSyncSetted();

    void gammaCryptionStart();
    void gammaCryption(uint8_t *out_data, uint8_t *in_data, uint32_t size);

    void setLibgost15(bool state);

private:

    void LSXEncryptData( uint8_t* data );

    void initRoundConsts();

    void inverseData(uint8_t *outData, uint8_t* data);
    void LTransformation(uint8_t *outData, uint8_t *data);
    void STransformation(uint8_t *outData, uint8_t *data);
    void XTransformation(uint8_t *out_data, uint8_t *data, uint8_t *key);

    uint8_t lFunc(uint8_t *data);

    uint8_t inverselFunc(uint8_t *data);
    void inverseSTransformation(uint8_t* data);
    void inverseLTransformation(uint8_t *data);

    void LSXTransformation(uint8_t* data, uint8_t* roundKey);
    void inverseLSXTransformation(uint8_t *data, uint8_t *roundKey);

    vector<uint8_t> polynomMult(vector<uint8_t> binPolynom1, vector<uint8_t> binPolynom2);
    vector<uint8_t> getBinaryVector(uint8_t number);
    void dataXor(uint8_t *out_data, uint8_t *data1, uint8_t *data2);
    uint8_t galoisMult(uint8_t polynom1, uint8_t polynom2);

    unsigned longAddition(unsigned char* a, unsigned sizeA,
            unsigned char* b, unsigned sizeB,
            unsigned char** sum);
    std::vector<uint8_t> longAddition(std::vector<uint8_t> a, std::vector<uint8_t> b);

    void generatingRoundKeys(vector<uint8_t> key);

    uint8_t roundKeys[10][16] = {{0}};
    uint8_t roundConsts[32][16] = {{0}};

    alignas(16) uint8_t libgost15_encrypt_roundKeys[10 * 16] = {0};
    alignas(16) uint8_t libgost15_decrypt_roundKeys[10 * 16] = {0};

    uint8_t sync[16] = {0};

    vector<uint8_t> gammaSync;

    static const int blockSize;
    static const int imitoLen;

    bool keySetted = false;
    bool syncSetted = false;

    bool isLibgost15Enabled = false;

    static const uint8_t generatingPolynom; //Полином x ^ 8 + x ^ 7 + x ^ 6 + x + 1

    //Коэффициенты в функции l из линейного перемешивания
    static const uint8_t lCoefficients[16];

    static const uint8_t B128[16];

    //Таблица замен
    static const uint8_t STable[256];

    //Обратная таблица замен
    static const uint8_t inverseSTable[256];

};

#endif
