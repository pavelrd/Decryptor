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
    void clearKey();
    void encrypt(uint8_t* encryptedBlock, uint8_t *block);
    void decrypt(uint8_t* block, uint8_t* encryptedBlock);
    bool isKeySetted();

    vector<uint8_t> gammaCryption(vector<uint8_t> data, vector<uint8_t> sync);

private:

    void LSXEncryptData( uint8_t* data );

    void initRoundConsts();

    void inverseData(uint8_t *outData, uint8_t* data);
    void LTransformation(uint8_t *outData, uint8_t *data);
    void STransformation(uint8_t *outData, uint8_t *data);
    void XTransformation(uint8_t *out_data, uint8_t *data, uint8_t *key);

    vector<uint8_t> imitoGeneration(vector<uint8_t> data, vector<vector<uint8_t>> roundKeys);
    vector<uint8_t> getImitoKey(vector<vector<uint8_t>> roundKeys);

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

    static const int blockSize;
    static const int imitoLen;

    uint8_t roundKeys[10][16] = {{0}};
    uint8_t roundConsts[32][16] = {{0}};

    bool keySetted = false;

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
