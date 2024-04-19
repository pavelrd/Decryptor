#include "threadworker.h"
#include <QDebug>
#include <QByteArray>
#include <QMessageBox>

void threadWorker::run()
{
if(isEncrypt)
{
    uint8_t block[16] = {0};
    uint8_t encryptedBlock[16] = {0};

    // ------- Запись длины файла в начало первого блока, который будет зашифрован

    uint32_t value = sourceFile->size();

    block[0] = value & 0xFF;

    block[1] = ( value >> 8 ) & 0xFF;

    block[2] = ( value >> 16 ) & 0xFF;

    block[3] = ( value >> 24 ) & 0xFF;

    // -------

    uint32_t j = 4; // Начинаем запись файла с 5 байта блока, так как в первые 4 байта записан размер файла

    emit progressChanged(0);

    QByteArray fileBytearray = sourceFile->readAll();

    sourceFile->close();

    delete sourceFile;

    for( uint32_t i = 0 ; i < fileBytearray.length(); i++ )
    {

        block[j] = fileBytearray.at(i);

        j++;

        if( j >= 16 )
        {

            j = 0;

            gost12_15_Worker->encrypt(encryptedBlock, block);

            encryptedFile->write((const char*)encryptedBlock, 16);

            for( uint32_t indexClear = 0 ; indexClear < 16; indexClear++)
            {
                block[indexClear] = 0x00;
            }

            emit progressChanged( ((double)i) / fileBytearray.length() * 100 );

        }

    }

    if( j != 0 )
    {

        gost12_15_Worker->encrypt(encryptedBlock, block);

        encryptedFile->write((const char*)encryptedBlock, 16);

    }

}
else
{

    QByteArray fileBytearray = sourceFile->readAll();

    sourceFile->close();

    delete sourceFile;

    uint8_t block[16] = {0};
    uint8_t decryptedBlock[16] = {0};

    uint32_t j = 0;
    uint32_t fileSize = 0;
    uint32_t fileCounter = 0;

    for( uint32_t i = 0 ; i < fileBytearray.length(); i++ )
    {

        block[j] = fileBytearray.at(i);

        j++;

        if( j >= 16 )
        {

            j = 0;

            gost12_15_Worker->decrypt(decryptedBlock, block);

            if( i < 16 )
            {

                // Первый блок, в нем первые 4 байта это длина файла, запоминаем эту длин

                fileSize |= decryptedBlock[0];
                fileSize |= ( ( (uint32_t) decryptedBlock[1] ) << 8 );
                fileSize |= ( ( (uint32_t) decryptedBlock[2] ) << 16 );
                fileSize |= ( ( (uint32_t) decryptedBlock[3] ) << 24 );

                if( fileSize < 12 ) // Файл полностью помещается в первом блоке. Чтобы это условие было выполнено файл должен быть размера 16 - 4 = 12
                {
                    encryptedFile->write( (const char*) decryptedBlock + 4, fileSize );
                    break;
                }
                else // Файл не помещается в одном блоке, запись уже считанной на текущий момент части файла.
                {
                   encryptedFile->write( (const char*) decryptedBlock + 4, 12 );
                   fileCounter += 12;
                }

            }
            else
            {

                // Второй и последующий блоки

                if( (fileCounter + 16) < fileSize )
                {
                    encryptedFile->write((const char*)decryptedBlock, 16);
                    fileCounter += 16;
                }
                else
                {
                    encryptedFile->write((const char*)decryptedBlock, fileSize - fileCounter);
                }

            }

            for( uint32_t indexClear = 0 ; indexClear < 16; indexClear++)
            {
                block[indexClear] = 0x00;
            }

            emit progressChanged( ((double)i) / fileBytearray.length() * 100 );

        }

    }



}

    emit progressChanged( 100 );

    emit cryptCompteted(isEncrypt);

    encryptedFile->close();

    delete encryptedFile;

}

void threadWorker::setEncrypt( QFile* _encryptedFile, QFile* _sourceFile, gost12_15 *_gost12_15_Worker, bool _isEncrypt )
{
    encryptedFile = _encryptedFile;
    sourceFile    = _sourceFile;
    gost12_15_Worker = _gost12_15_Worker;
    isEncrypt = _isEncrypt;
}
