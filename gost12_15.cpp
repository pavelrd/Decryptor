#include <cstring>

#include "gost12_15.h"


/**
* \brief Функция умножения чисел в конечном поле над неприводимым полиномом.
*
* Умножение происходит над полем Галуа GF(2^8) над неприводимым полиномом x^8 + x^7 + x^6 + x + 1.
* Суть функции в умножении в столбик с добавлением числа 0xс3, которое и представляет нужный нам полином.
*
* \param [in] polynom1 – первый многочлен для умножения.
* \param [in] polynom2 – второй многочлен для умножения.
* \return возвращает результат умножения двух многочленов.
*/
uint8_t gost12_15::galoisMult(uint8_t polynom1, uint8_t polynom2)
{
    uint8_t multRes = 0;
    uint8_t highBit;

    for (int i = 0; i < 8; i++) {
        if (polynom2 & 1) {
            multRes = multRes ^ polynom1;
        }

        highBit = polynom1 & 0x80; //запомнить старший бит
        polynom1 = static_cast<uint8_t>(polynom1 << 1);

        if (highBit) {
            polynom1 = polynom1 ^ generatingPolynom; // Порождающий полином вычитается из polynom1
        }

        polynom2 = static_cast<uint8_t>(polynom2 >> 1);
    }

    return multRes;
}


/**
* \brief Функция умножения байтовой последовательности на коэффициенты l функции.
*
* Каждый байт из блока умножается с помощью функции galoisMult на один из коэффициентов из ряда lCoefficients
* в зависимости от порядкового номера байта. Байты складываются между собой по модулю 2 (xor).
* Операция xor является сложением над полем Галуа GT(2^8) с неприводимым многочленом x^8 + x^7 + x^6 + x + 1.
* Функция используется при шифровании.
*
* \param [in] data – открытая входная последовательность байт размера 16.
* \return возвращает полином 7-й степени, который представлен в числовом виде.
*/
uint8_t gost12_15::lFunc(uint8_t* data)
{

    uint8_t la = 0;

    for (int i = 0; i < blockSize; i++)
    {
        la = la ^ galoisMult(data[i], lCoefficients[i]);
    }

    return la;

}


/**
* \brief Функция обратная к lFunc.
*
* В функции также каждый байт из блока умножается с помощью функции galoisMult на один из коэффициентов
* из ряда lCoefficients, но порядок этих коэффициентов изменен.
* Функция используется в алгоритме расшифрования.
*
* \param [in] data – зашифрованная входная последовательность байт размера 16.
* \return возвращает полином 7-й степени, который представлен в числовом виде.
*/
uint8_t gost12_15::inverselFunc(uint8_t* data)
{
    uint8_t la = 0;

    for (int i = blockSize - 2; i >= 0; i--) {
        la = la ^ galoisMult(data[i], lCoefficients[i + 1]);
    }
    la = la ^ galoisMult(data[blockSize - 1], lCoefficients[0]);

    return la;
}


/**
* \brief Функция линейного преобразования.
*
* Линейное перемешивание L шифра «Кузнечик» может быть описано с помощью линейного регистра сдвига R:
* 1. Для каждого байта из шестнадцати байт блока входной последовательности вычисляется функция lFunc(data).
* 2. Полученный на предыдущем шаге результат записывается первым в строку байтов, затем записываются все байты
*    входной последовательности data, кроме младшего (последнего) .
* Таким образом, фактически производится сдвиг строки байтов а вправо на один байт.
* Цикл выполняется 16 раз, функция используется при зашифровании данных.
*
* \param [in] data – открытая входная последовательность байт размера 16.
* \return возвращает линейно преобразованную входную последовательность .
*/

void gost12_15::LTransformation(uint8_t* outData, uint8_t* data)
{

    memcpy(outData, data, blockSize);

    for (int i = 0; i < blockSize; i++)
    {
        uint8_t la = lFunc(outData);
        for (int j = 0; j < blockSize - 1; j++)
        {
            outData[j] = outData[j + 1];
        }
        outData[blockSize - 1] = la;
    }

}


/**
* \brief Функция обратного линейного преобразования.
*
* 1. Для каждого байта из шестнадцати байт блока входной последовательности вычисляется функция inverselFunc(data).
* 2. Полученный на предыдущем шаге результат записывается последним в строку байтов, затем записываются все байты
*    входной последовательности data, кроме старшего (первого).
* Цикл выполняется 16 раз, функция используется при расшифровании данных.
*
* \param [in] data – зашифрованная входная последовательность байт размера 16.
* \return возвращает расшифрованную входную последовательность.
*/
void gost12_15::inverseLTransformation(uint8_t* data)
{

    uint8_t rData[blockSize];

    memcpy(rData, data, blockSize);

    for (int i = 0; i < blockSize; i++)
    {
        uint8_t la = inverselFunc(rData);
        for (int j = blockSize - 1; j > 0; j--)
        {
            rData[j] = rData[j - 1];
        }
        rData[0] = la;
    }

    memcpy(data, rData, blockSize);

}


/**
* \brief Функция нелинейного преобразования.
*
* Нелинейное S преобразовании в алгоритме выполняется через замену.
* К каждому байту применяется нелинейная подстановка, задаваемая массивом STable.
* Новое значение элемента data (sData[i]) определяется как STable[data[i]], где текущее
* значение data[i] выступает в роли индекса нового значения sData[i].
* Функция используется в зашифровании данных.
*
* \param [in] data – открытая входная последовательность байт размера 16.
* \return возвращает нелинейно преобразованную входную последовательность.
*/

void gost12_15::STransformation(uint8_t* outData, uint8_t* data)
{

    for (int i = 0; i < blockSize; i++)
    {
        outData[i] = STable[data[i]];
    }

}


/**
* \brief Функция обратного нелинейного преобразования.
*
* К каждому байту применяется обратная нелинейная подстановка, задаваемая массивом inverseSTable.
* Новое значение элемента data (sData[i]) определяется как inverseSTable[data[i]], где текущее
* значение data[i] выступает в роли индекса нового значения sData[i].
* Функция используется в расшифровании данных.
*
* \param [in] data – зашифрованная входная последовательность байт размера 16.
* \return возвращает расшифрованную входную последовательно.
*/
void gost12_15::inverseSTransformation(uint8_t* data)
{

    for (int i = 0; i < blockSize; i++)
    {
        data[i] = inverseSTable[data[i]];
    }

}


/**
* \brief Функция X преобразования.
*
* Функция представляет собой классическое сложение по модулю 2, или xor.
* Поскольку xor обратен сам себе, функция используется для зашифрования и расшифрования данных.
* Логика функции заключается в побитовом наложении ключа на входную последовательность.
*
* \param [in] data – входная последовательность байт размера 16.
* \param [in] key - раундовый ключ размера 16 байт.
* \return возвращает результат наложения раундового ключа на входную последовательность.
*/
void gost12_15::XTransformation(uint8_t* out_data, uint8_t* data, uint8_t* key)
{

    for (int i = 0; i < blockSize; i++)
    {
        out_data[i] = data[i] ^ key[i];
    }

}


/**
* \brief Функция инициализации раундовых ключей и констант.
*
* В функции выделяется необходимая память для десяти раундовых ключей, каждый из которых
* имеет размер 16 байт (матрица 10 на 16).
* Так же выделяется память для тридцати двух раундовых констант, каждая из которых имеет
* размер 16 байт (матрица 32 на 16).
* Функция вызывается один раз при старте программы, т.к. константы всегда вырабатываются
* идентичные для каждого этапа развертки ключей.
*
*/

void gost12_15::initRoundConsts()
{

    for (size_t i = 0; i < 32; i++)
    {
        for (size_t j = 0; j < 16; j++)
        {
            roundConsts[i][j] = 0;
        }
    }

    for (size_t i = 0; i < 32; i++)
    {

        roundConsts[i][blockSize - 1] = static_cast<uint8_t>(i + 1);

        inverseData(roundConsts[i], roundConsts[i] );

        LTransformation(roundConsts[i], roundConsts[i]);

        inverseData(roundConsts[i], roundConsts[i]);

    }

/*
    for( uint8_t i = 0 ; i < 32; i++ )
    {
        QString str = "";
        for(uint8_t j = 0 ; j < 16; j++)
        {
            str += QString::number(roundConsts[i][j],16) + " ";
        }

        qDebug() << str;
    }
*/

}


/**
* \brief Функция генерации ключевого расписания (выработка раундовых ключей).
*
* Для зашифрования и расшифрования требуется десять раундовых ключей, а для их получения необходимы
* тридцать две раундовые константы, которые получаются из порядкового номера итерации с помощью
* линейного преобразования.
* Раундовые константы вырабатываются с помощью функции initConstsAndRoundKeys при старте программы.
*
* Первые два раундовых ключа k1 и k2 получаются разбиением исходного ключа key на две части.
* Далее для выработки каждой пары раундовых ключей используется 8-раундовый алгоритм со структурой Фейстеля,
* в котором функция раундового преобразования определяется как последовательность преобразований LSX,
* а в качестве раундовых ключей используются раундовые константы.
*
* \param [in] key – главный ключ длиной 32 байта.
* \return возвращает матрицу раундовых ключей размера 10 (количество ключей) на 16 (размер блока).
*/

void gost12_15::generatingRoundKeys(vector<uint8_t> key)
{

    for (int i = 0; i < blockSize; i++)
    {
        roundKeys[0][i] = key[i];
    }

    for (int i = 0; i < blockSize; i++)
    {
        roundKeys[1][i] = key[i + blockSize];
    }

    uint8_t k1[blockSize];

    for( int i = 0 ; i < blockSize; i++ )
    {
        k1[i] = roundKeys[0][i];
    }

    uint8_t k2[blockSize];

    for( int i = 0 ; i < blockSize; i++ )
    {
        k2[i] = roundKeys[1][i];
    }

    uint8_t lsx[blockSize] = {0};

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 8; j++) {
            if (j % 2 == 0) {
                XTransformation( lsx, k1, roundConsts[8 * i + j]);
                inverseData(lsx,lsx);
                STransformation(lsx, lsx);
                LTransformation(lsx,lsx);
                inverseData(lsx, lsx);
                dataXor( k2 ,lsx, k2);
            }
            else if (j % 2 == 1) {
                XTransformation( lsx, k2, roundConsts[8 * i + j]);
                inverseData( lsx, lsx);
                STransformation(lsx, lsx);
                LTransformation(lsx, lsx);
                inverseData(lsx, lsx);
                dataXor(k1, lsx, k1);
            }
        }
    /*
        QString str = "";

        for(int index = 0 ; index < 16; index++)
        {
            str += QString::number(k1[index], 16) + " ";
        }

        for(int index = 0 ; index < 16; index++)
        {
            str += QString::number(k2[index], 16) + " ";
        }

        qDebug() << str;
    */
        memcpy( roundKeys[i * 2 + 2], k1, 16 );
        memcpy( roundKeys[i * 2 + 3], k2, 16 );
    }

}


/**
* \brief Функция одного раунда LSX преобразования.
*
* Один раунд LSX преобразования включает в себя:
* 1. Побитовое наложение раундового ключа на исходную последовательность (XTransformation).
* 2. Нелинейное преобразование (STransformation).
* 3. Линейное преобразование (LTransformation).
*
* \remark Поскольку в алгоритме исходная последовательность нумеруется с младших битов (справа),
* требуется производить разворот (inverseData) исходной последовательности, т.к. на вход она подается
* с нумерацией со старших битов (слева).
*
* \param [in] data – исходная последовательность размера 16 байт.
* \param [in] roundKey - раундовый ключ размера 16 байт.
* \return возвращает результат одного раунда LSX преобразования.
*/
void gost12_15::LSXTransformation(uint8_t* data, uint8_t* roundKey)
{

    XTransformation( data, data, roundKey);
    inverseData(data, data);

    STransformation(data, data);
    LTransformation(data, data);
    inverseData(data, data);

}


/**
* \brief Функция одного раунда обратного LSX преобразования.
*
* Один раунд обратного LSX преобразования включает в себя:
* 1. Побитовое наложение раундового ключа на исходную последовательность (XTransformation).
* 2. Обратное линейное преобразование (inverseSTransformation).
* 3. Обратное нелинейное преобразование (inverseLTransformation).
*
* \remark Поскольку в алгоритме исходная последовательность нумеруется с младших битов (справа),
* требуется производить разворот (реверс) исходной последовательности, т.к. на вход она подается
* с нумерацией со старших битов (слева).
*
* \param [in] data – исходная последовательность размера 16 байт.
* \param [in] roundKey - раундовый ключ размера 16 байт.
* \return возвращает результат одного раунда обратного LSX преобразования.
*/
void gost12_15::inverseLSXTransformation(uint8_t* data, uint8_t* roundKey)
{

    XTransformation(data, data, roundKey);
    inverseData(data, data);

    inverseLTransformation(data);
    inverseSTransformation(data);
    inverseData(data, data);

}


/**
* \brief Функция побитового сложения по модулю 2 (xor).
*
* \param [in] data1 – первый вектор.
* \param [in] data2 – второй вектор.
* \return возвращает результат побитового сложения по модулю 2 двух векторов.
*/
void gost12_15::dataXor(uint8_t* out_data, uint8_t* data1, uint8_t* data2)
{

    for (int i = 0; i < blockSize; i++)
    {
        out_data[i] = data1[i] ^ data2[i];
    }

}


/**
* \brief Функция классического умножения двух многочленов в бинарном виде.
*
* \param [in] binPolynom1 – первый многочлен в бинарном виде.
* \param [in] binPolynom1 – второй многочлен в бинарном виде.
* \return возвращает результат умножения двух многочленов в бинарном виде.
*/
vector<uint8_t> gost12_15::polynomMult(vector<uint8_t> binPolynom1, vector<uint8_t> binPolynom2) {
    vector<uint8_t> binMultRes(binPolynom1.size() + binPolynom2.size(), 0);

    for (size_t i = 0; i < binPolynom1.size(); i++) {
        for (size_t j = 0; j < binPolynom2.size(); j++) {
            binMultRes[i + j + 1] = static_cast<uint8_t>(binMultRes[i + j + 1] ^ (binPolynom1[i] & binPolynom2[j]));
        }
    }

    return binMultRes;
}


/**
* \brief Функция получения бинарного представления числа в векторе.
*
* \param [in] number – число в десятичном представлении.
* \return возвращает вектор двоичного представления исходного числа.
*/
vector<uint8_t> gost12_15::getBinaryVector(uint8_t number) {
    vector<uint8_t> binNumber(8, 0);
    bitset<8> binSeq = bitset<8>(number);

    for (size_t i = 0; i < binNumber.size(); i++) {
        binNumber[i] = binSeq[binNumber.size() - i - 1];
    }

    return binNumber;
}


/**
* \brief Функция разворота входной последовательности.
*
* \param [in] data – исходная последовательность.
* \return возвращает развернутую исходную последовательность.
*/
void gost12_15::inverseData(uint8_t* outData, uint8_t* data)
{

    uint8_t invData[16] = {0};

    for (int i = 0; i < blockSize; i++)
    {
        invData[i] = data[blockSize - i - 1];
    }

    for( int i = 0 ; i < blockSize; i++ )
    {
        outData[i] = invData[i];
    }

}

/**
 * \brief Складывает два длинных числа друг с другом. Порядок хранения байт: младший разряд в конце.
 * \details Числа должны быть записаны в памяти. А память под результат выделяется внутри функции.
 * \details Функция взята откуда-то с просторов интернета, но проверена на корректность.
 * \details ToDo: Не очень хорошо выделять память в одной области видимости, а очищать в другой. Эту функцию стоит обдумать и переработать.
 * \details ToDo: Поменять Си-шные инструменты для работы с памятью на C++-ные.
 * \param [in] a Указатель на область памяти, в которой хранится первое слагаемое.
 * \param [in] sizeA Длина в байтах первого слагаемого.
 * \param [in] b Указатель на область памяти, в которой хранится второе слагаемое.
 * \param [in] sizeB Длина в байтах второго слагаемого.
 * \param [out] sum Указатель на указатель на область памяти, в которой сохранён результат.
 * \return Длина результата.
 */
unsigned gost12_15::longAddition(unsigned char* a, unsigned sizeA,
                      unsigned char* b, unsigned sizeB,
                      unsigned char** sum)
{
    unsigned lengthResult;
    if (sizeA > sizeB)
        lengthResult = sizeA + 1;
    else
        lengthResult = sizeB + 1;

    const auto tmpSum = static_cast<unsigned char*>(calloc(lengthResult, 1));
    const auto shiftA = static_cast<unsigned char*>(calloc(lengthResult, 1));
    memcpy(shiftA + lengthResult - sizeA, a, sizeA);
    const auto shiftB = static_cast<unsigned char*>(calloc(lengthResult, 1));
    memcpy(shiftB + lengthResult - sizeB, b, sizeB);

    for (unsigned i = lengthResult - 1; i >= 1; --i)
    {
        const unsigned short tmpAddition = static_cast<unsigned short>(shiftA[i]) +
                                           static_cast<unsigned short>(shiftB[i]) +
                                           static_cast<unsigned short>(tmpSum[i]); // суммируем последние разряды чисел и перенесённый разряд из предыдущего сложения
        tmpSum[i] = tmpAddition % 256; // если есть разряд для переноса он отсекается
        tmpSum[i - 1] += (tmpAddition / 256); // если есть разряд для переноса, переносим его в следующее сложение
    }

    if (tmpSum[0] == 0)
    {
        --lengthResult;
        *sum = static_cast<unsigned char*>(calloc(lengthResult, 1));
        memcpy(*sum, tmpSum + 1, lengthResult);
    }
    else
    {
        *sum = static_cast<unsigned char*>(calloc(lengthResult, 1));
        memcpy(*sum, tmpSum, lengthResult);
    }
    free(tmpSum);
    free(shiftA);
    free(shiftB);
    return lengthResult;
}

/**
 * \brief С++-style интерфейс для функции сложения длинных чисел. Порядок хранения байт: младший разряд в конце.
 * @param a Первое слагаемое.
 * @param b Второе слагаемое.
 * @return Сумма.
 */
std::vector<uint8_t> gost12_15::longAddition(std::vector<uint8_t> a, std::vector<uint8_t> b)
{
    unsigned char* sum;
    auto length = longAddition(a.data(), a.size(), b.data(), b.size(), &sum);
    std::vector<uint8_t> result(sum, sum + length);
    free(sum);
    return result;
}


/**
* \brief Функция выработки имитовставки.
*
* Процедура вычисления имитовставки описывается следующим образом: на каждом шаге шифруется побитовый XOR
* между текущим значением имитовставки и соответствующим блоком исходного кода. На последнем этапе,
* перед шифрованием необходимо сделать XOR с ключом имитовставки. После этого, за имитовставку берется
* первая половина зашифрованного текста.
*
* \param [in] data – исходная последовательно открытого текста.
* \param [in] roundKeys - матрица раундовых ключей.
* \return возвращает вычисленную имитовставку.
*/
vector<uint8_t> gost12_15::imitoGeneration(vector<uint8_t> data, vector<vector<uint8_t>> roundKeys) {
    /*
    vector<uint8_t> imito(imitoLen, 0);
    vector<uint8_t> blockData(blockSize, 0);
    int blockCount = static_cast<int>(data.size() / blockSize);

    for (int j = 0; j < blockSize; j++) {
        blockData[j] = data[j];
    }

    blockData = LSXEncryptData(blockData, roundKeys);

    for (int i = 1; i < blockCount - 1; i++) {
        for (int j = 0; j < blockSize; j++) {
            blockData[j] = blockData[j] ^ data[i*blockSize + j];
        }

        blockData = LSXEncryptData(blockData, roundKeys);
    }

    vector<uint8_t> imitoKey = getImitoKey(roundKeys);
    for (int j = 0; j < blockSize; j++) {
        blockData[j] = blockData[j] ^ data[(blockCount - 1)*blockSize + j];
        blockData[j] = blockData[j] ^ imitoKey[j];
    }

    blockData = LSXEncryptData(blockData, roundKeys);

    for (int i = 0; i < imitoLen; i++) {
        imito[i] = blockData[i];
    }
    */
    vector<uint8_t> imito(imitoLen, 0);
    return imito;
}


/**
* \brief Функция выработки ключа для имитовставки.
*
* Для начала шифруется нулевая последовательность размера 16 байт. Результатом будет являться блок imitoKey.
* Если в результате первый байт блока imitoKey равен нулю, то результатом является блок imitoKey,
* побитово сдвинутый на единицу влево.
* В противном случае, результатом является XOR блока imitoKey, побитово сдвинутого на единицу влево, и константы
* В128.
*
* \param [in] roundKeys - матрица раундовых ключей.
* \return возвращает вычисленный ключ для имитовставки.
*/
vector<uint8_t> gost12_15::getImitoKey(vector<vector<uint8_t>> roundKeys) {
    /*
    vector<uint8_t> imitoKey(blockSize, 0);
    uint8_t overflowFlag;
    uint8_t overflow = 0;

    imitoKey = LSXEncryptData(imitoKey, roundKeys);

    for (int i = blockSize - 1; i >= 0; i--) {
        overflowFlag = imitoKey[i] < 0x80 ? 0 : 1;
        imitoKey[i] = static_cast<uint8_t>(imitoKey[i] * 0x02 + overflow);
        overflow = overflowFlag;
    }

    if (imitoKey[blockSize - 1] != 0) {
        for (int i = 0; i < blockSize; i++) {
            imitoKey[i] = imitoKey[i] ^ B128[i];
        }
    }
    */
    vector<uint8_t> imitoKey(blockSize, 0);

    return imitoKey;
}

void gost12_15::setKey(const char* key)
{

    vector<uint8_t> generalKey(32, 0);

    for( unsigned int i = 0 ; ( i < strlen(key) ) && ( i < 32) ; i++ )
    {
        generalKey[i] = key[i];
    }

    initRoundConsts();

    generatingRoundKeys(generalKey);

    keySetted = true;

}

void gost12_15::setKey_HEX(const char* key)
{
    vector<uint8_t> generalKey(32, 0);

    for( unsigned int i = 0 ; ( i < strlen(key) ) && ( i < 32) ; i++ )
    {

        char bufstr[3] = {0};

        bufstr[0] = key[i];

        if( ( i + 1 ) < strlen(key) )
        {
            bufstr[1] = key[i+1];
        }

        generalKey[i] = strtol(bufstr, NULL, 16);

    }

    initRoundConsts();

    generatingRoundKeys(generalKey);

    keySetted = true;
}

void gost12_15::setSync(const char *_sync)
{
    for(uint8_t i = 0; i < blockSize / 2; i++)
    {
        sync[i] = 0;
    }

    for (uint8_t i = 0; (i < (blockSize / 2) ) && (i < strlen(_sync)); i++) {

        sync[i] = _sync[i];
    }
}

void gost12_15::setSync_HEX(const char *_sync)
{

    for(uint8_t i = 0; i < blockSize / 2; i++)
    {
        sync[i] = 0;
    }

    for (uint8_t i = 0; (i < (blockSize / 2) ) && (i < strlen(_sync)); i++)
    {

        char bufstr[3] = {0};

        bufstr[0] = _sync[i];

        if( ( i + 1 ) < strlen(_sync) )
        {
            bufstr[1] = _sync[i+1];
        }

        sync[i] = strtol(bufstr, NULL, 16);  //  _sync[i];

    }

}

void gost12_15::encrypt(uint8_t* encryptedBlock, uint8_t* block)
{

    if( !keySetted )
    {
        return;
    }

    for (int i = 0; i < 9; i++)
    {
        LSXTransformation( block, roundKeys[i] );
    }

    XTransformation( encryptedBlock, block, roundKeys[9] );

}

void gost12_15::decrypt(uint8_t* block, uint8_t* encryptedBlock)
{

    if( !keySetted )
    {
        return;
    }

    for (int i = 9; i > 0; i--)
    {
        inverseLSXTransformation(encryptedBlock, roundKeys[i]);
    }

    XTransformation(block, encryptedBlock, roundKeys[0]);

}

bool gost12_15::isKeySetted()
{
    return keySetted;
}

bool gost12_15::isSyncSetted()
{
    return syncSetted;
}

void gost12_15::clearKey()
{
    keySetted = false;
}

void gost12_15:: clearSync()
{
    syncSetted = false;
}


const uint8_t gost12_15::generatingPolynom = 0xc3; //Полином x ^ 8 + x ^ 7 + x ^ 6 + x + 1

const uint8_t gost12_15::lCoefficients[16] =
{
    1, 148, 32, 133, 16, 194, 192, 1,
    251, 1, 192, 194, 16, 133, 32, 148
};

const uint8_t gost12_15::B128[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87
};

//Таблица замен
const uint8_t gost12_15::STable[256] = {
    0xfc, 0xee, 0xdd, 0x11, 0xcf, 0x6e, 0x31, 0x16,
    0xfb, 0xc4, 0xfa, 0xda, 0x23, 0xc5, 0x4, 0x4d,
    0xe9, 0x77, 0xf0, 0xdb, 0x93, 0x2e, 0x99, 0xba,
    0x17, 0x36, 0xf1, 0xbb, 0x14, 0xcd, 0x5f, 0xc1,
    0xf9, 0x18, 0x65, 0x5a, 0xe2, 0x5c, 0xef, 0x21,
    0x81, 0x1c, 0x3c, 0x42, 0x8b, 0x01, 0x8e, 0x4f,
    0x05, 0x84, 0x02, 0xae, 0xe3, 0x6a, 0x8f, 0xa0,
    0x06, 0x0b, 0xed, 0x98, 0x7f, 0xd4, 0xd3, 0x1f,
    0xeb, 0x34, 0x2c, 0x51, 0xea, 0xc8, 0x48, 0xab,
    0xf2, 0x2a, 0x68, 0xa2, 0xfd, 0x3a, 0xce, 0xcc,
    0xb5, 0x70, 0x0e, 0x56, 0x08, 0x0c, 0x76, 0x12,
    0xbf, 0x72, 0x13, 0x47, 0x9c, 0xb7, 0x5d, 0x87,
    0x15, 0xa1, 0x96, 0x29, 0x10, 0x7b, 0x9a, 0xc7,
    0xf3, 0x91, 0x78, 0x6f, 0x9d, 0x9e, 0xb2, 0xb1,
    0x32, 0x75, 0x19, 0x3d, 0xff, 0x35, 0x8a, 0x7e,
    0x6d, 0x54, 0xc6, 0x80, 0xc3, 0xbd, 0x0d, 0x57,
    0xdf, 0xf5, 0x24, 0xa9, 0x3e, 0xa8, 0x43, 0xc9,
    0xd7, 0x79, 0xd6, 0xf6, 0x7c, 0x22, 0xb9, 0x03,
    0xe0, 0x0f, 0xec, 0xde, 0x7a, 0x94, 0xb0, 0xbc,
    0xdc, 0xe8, 0x28, 0x50, 0x4e, 0x33, 0x0a, 0x4a,
    0xa7, 0x97, 0x60, 0x73, 0x1e, 0x00, 0x62, 0x44,
    0x1a, 0xb8, 0x38, 0x82, 0x64, 0x9f, 0x26, 0x41,
    0xad, 0x45, 0x46, 0x92, 0x27, 0x5e, 0x55, 0x2f,
    0x8c, 0xa3, 0xa5, 0x7d, 0x69, 0xd5, 0x95, 0x3b,
    0x07, 0x58, 0xb3, 0x40, 0x86, 0xac, 0x1d, 0xf7,
    0x30, 0x37, 0x6b, 0xe4, 0x88, 0xd9, 0xe7, 0x89,
    0xe1, 0x1b, 0x83, 0x49, 0x4c, 0x3f, 0xf8, 0xfe,
    0x8d, 0x53, 0xaa, 0x90, 0xca, 0xd8, 0x85, 0x61,
    0x20, 0x71, 0x67, 0xa4, 0x2d, 0x2b, 0x09, 0x5b,
    0xcb, 0x9b, 0x25, 0xd0, 0xbe, 0xe5, 0x6c, 0x52,
    0x59, 0xa6, 0x74, 0xd2, 0xe6, 0xf4, 0xb4, 0xc0,
    0xd1, 0x66, 0xaf, 0xc2, 0x39, 0x4b, 0x63, 0xb6
};

//Обратная таблица замен
const uint8_t gost12_15::inverseSTable[256] =
{
    0xa5, 0x2d, 0x32, 0x8f, 0x0e, 0x30, 0x38, 0xc0,
    0x54, 0xe6, 0x9e, 0x39, 0x55, 0x7e, 0x52, 0x91,
    0x64, 0x03, 0x57, 0x5a, 0x1c, 0x60, 0x07, 0x18,
    0x21, 0x72, 0xa8, 0xd1, 0x29, 0xc6, 0xa4, 0x3f,
    0xe0, 0x27, 0x8d, 0x0c, 0x82, 0xea, 0xae, 0xb4,
    0x9a, 0x63, 0x49, 0xe5, 0x42, 0xe4, 0x15, 0xb7,
    0xc8, 0x06, 0x70, 0x9d, 0x41, 0x75, 0x19, 0xc9,
    0xaa, 0xfc, 0x4d, 0xbf, 0x2a, 0x73, 0x84, 0xd5,
    0xc3, 0xaf, 0x2b, 0x86, 0xa7, 0xb1, 0xb2, 0x5b,
    0x46, 0xd3, 0x9f, 0xfd, 0xd4, 0x0f, 0x9c, 0x2f,
    0x9b, 0x43, 0xef, 0xd9, 0x79, 0xb6, 0x53, 0x7f,
    0xc1, 0xf0, 0x23, 0xe7, 0x25, 0x5e, 0xb5, 0x1e,
    0xa2, 0xdf, 0xa6, 0xfe, 0xac, 0x22, 0xf9, 0xe2,
    0x4a, 0xbc, 0x35, 0xca, 0xee, 0x78, 0x05, 0x6b,
    0x51, 0xe1, 0x59, 0xa3, 0xf2, 0x71, 0x56, 0x11,
    0x6a, 0x89, 0x94, 0x65, 0x8c, 0xbb, 0x77, 0x3c,
    0x7b, 0x28, 0xab, 0xd2, 0x31, 0xde, 0xc4, 0x5f,
    0xcc, 0xcf, 0x76, 0x2c, 0xb8, 0xd8, 0x2e, 0x36,
    0xdb, 0x69, 0xb3, 0x14, 0x95, 0xbe, 0x62, 0xa1,
    0x3b, 0x16, 0x66, 0xe9, 0x5c, 0x6c, 0x6d, 0xad,
    0x37, 0x61, 0x4b, 0xb9, 0xe3, 0xba, 0xf1, 0xa0,
    0x85, 0x83, 0xda, 0x47, 0xc5, 0xb0, 0x33, 0xfa,
    0x96, 0x6f, 0x6e, 0xc2, 0xf6, 0x50, 0xff, 0x5d,
    0xa9, 0x8e, 0x17, 0x1b, 0x97, 0x7d, 0xec, 0x58,
    0xf7, 0x1f, 0xfb, 0x7c, 0x09, 0x0d, 0x7a, 0x67,
    0x45, 0x87, 0xdc, 0xe8, 0x4f, 0x1d, 0x4e, 0x04,
    0xeb, 0xf8, 0xf3, 0x3e, 0x3d, 0xbd, 0x8a, 0x88,
    0xdd, 0xcd, 0x0b, 0x13, 0x98, 0x02, 0x93, 0x80,
    0x90, 0xd0, 0x24, 0x34, 0xcb, 0xed, 0xf4, 0xce,
    0x99, 0x10, 0x44, 0x40, 0x92, 0x3a, 0x01, 0x26,
    0x12, 0x1a, 0x48, 0x68, 0xf5, 0x81, 0x8b, 0xc7,
    0xd6, 0x20, 0x0a, 0x08, 0x00, 0x4c, 0xd7, 0x74
};

const int gost12_15::blockSize = 16;
const int gost12_15::imitoLen = 8;

void gost12_15::gammaCryptionStart()
{

    if( gammaSync.size() != 16 )
    {
        gammaSync.resize(16,0);
    }

    for( int i = 0 ; i < 16; i++ )
    {
        gammaSync[i] = 0;
    }

    for (int i = 0; i < blockSize / 2; i++)
    {
        gammaSync[i] = sync[i];
    }

}

/**
* \brief Функция режима гаммирования.
*
* Зашифровывание и расшифровывание данных в режиме гаммирования.
* Исходное значение (gammaSync) - уникальная синхропосылка дополняется нулями до размера блока,
* но на последнем место ставится значение счётчика, равное номеру итерации (начиная с 1).
* Для каждого блока исходной последовательности, gammaSync шифруется с помощью LSX преобразования.
* Затем зашифрованная gammaSync побитово накладывается на открытый исходный текст.
*
* \param [in] data – исходная последовательно открытого текста.
* \param [in] sync – синхропосылка.
* \param [in] roundKeys - матрица раундовых ключей.
* \return возвращает работы режима гаммирования - зашифрованную (расшифрованную) исходную последовательность.
*/

void gost12_15::gammaCryption( uint8_t* out_data, uint8_t* in_data, uint32_t size )
{

    uint32_t blockCount = static_cast<int>(size / blockSize);

    if((size % blockSize) != 0)
    {
         blockCount++;
    }

    uint8_t encSync[blockSize];

    for (uint32_t i = 0; i < blockCount; i++)
    {

        for(uint8_t j = 0; j < blockSize; j++)
        {
            encSync[j] = gammaSync[j];
        }

        LSXEncryptData( encSync );

        for (uint8_t j = 0; j < blockSize; j++)
        {
            if( (blockSize*i + j) < size )
            {
                out_data[blockSize*i + j] = in_data[blockSize*i + j] ^ encSync[j];
            }
            else
            {
                break;
            }
        }

        gammaSync = longAddition(gammaSync, {0x01});
        if(gammaSync.size() > blockSize) { // Если сложение увеличило длину, то обрезаем.
            gammaSync.erase(gammaSync.begin());
        }

    }

}


/**
* \brief Функция LSX преобразования.
*
* Открытая входная последовательность проходит 9 раундов LSX преобразования.
* На последнем 10м раунде происходит побитовое наложение раундового ключа.
*
* \param [in] data – открытая входная последовательность размера 16 байт.
* \param [in] roundKeys - матрица раундовых ключей.
* \return возвращает результат преобразования LSX для исходной последовательности.
*/

void gost12_15::LSXEncryptData( uint8_t* data )
{

    for (int i = 0; i < 9; i++)
    {
        LSXTransformation( data, roundKeys[i] );
    }

    XTransformation( data, data, roundKeys[9]);

}
