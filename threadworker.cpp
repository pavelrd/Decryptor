#include "threadworker.h"
#include <QDebug>
#include <QByteArray>
#include <QMessageBox>

void threadWorker::run()
{

    if( cryptMode == ENCRYPT_SIMPLE )
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

        emit progressChanged(0);

        int progressValue = 0;

        // Начинаем запись файла с 5 байта блока, так как в первые 4 байта записан размер файла

        int currentReadedBytes = 4;

        currentReadedBytes += sourceFile->read( (char*)block+4, 12 );

        do
        {

            if( currentReadedBytes >= 16 )
            {

                sync.lock();

                if(pauseFlag)
                {
                    pauseCond.wait(&sync); // in this place, your thread will stop to execute until someone calls resume
                }

                sync.unlock();

                gost12_15_Worker->encrypt(encryptedBlock, block);

                encryptedFile->write((const char*)encryptedBlock, 16);

                int currentProgressValue = ( (int) ( ((double)sourceFile->pos()) / sourceFile->size() * 100 ) );

                if( progressValue < currentProgressValue )
                {
                    progressValue = currentProgressValue;
                    emit progressChanged(progressValue);
                }

            }
            else
            {

                // Файл закончен, при этом блок заполнен не до конца

                // Дополнение блока нулями

                for( int i = currentReadedBytes; i < 16; i++)
                {
                    block[i] = 0x00;
                }

                gost12_15_Worker->encrypt(encryptedBlock, block);

                encryptedFile->write((const char*)encryptedBlock, 16);

                break;

            }

        } while( (currentReadedBytes = sourceFile->read( (char*)block, 16 ) ) > 0 );



        emit cryptCompteted(1);

    }
    else if( cryptMode == DECRYPT_SIMPLE )
    {

        uint8_t block[16] = {0};

        uint32_t fileSize = 0;
        uint32_t fileCounter = 0;

        int currentReadedBytes = 0;
        int progressValue = 0;

        // Начинаем запись файла с 5 байта блока, так как в первые 4 байта записан размер файла

        while( ( currentReadedBytes = sourceFile->read( (char*)block, 16 ) ) > 0 )
        {

            sync.lock();
            if(pauseFlag)
            {
                pauseCond.wait(&sync); // in this place, your thread will stop to execute until someone calls resume
            }
            sync.unlock();

            uint8_t decryptedBlock[16];

            gost12_15_Worker->decrypt(decryptedBlock, block);

            if( sourceFile->pos() <= 16 )
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

            int currentProgressValue = ( (int) ( ((double) sourceFile->pos()) / sourceFile->size() * 100 ) );

            if( progressValue < currentProgressValue )
            {
                progressValue = currentProgressValue;
                emit progressChanged(progressValue);
            }


        }



        emit cryptCompteted(0);

    }
    else if( ( cryptMode == ENCRYPT_GAMMA) || ( cryptMode == DECRYPT_GAMMA ) )
    {

        vector<uint8_t> in_data(sourceFile->size(), 0);

        QByteArray ba = sourceFile->readAll();

        for( uint32_t i = 0 ; i < sourceFile->size(); i++ )
        {
            in_data[i] = ba.at(i);
        }

        vector<uint8_t> out_data = gost12_15_Worker->gammaCryption(in_data);

        QByteArray outByteArray;

        for( uint32_t i = 0; i < out_data.size(); i++ )
        {
            outByteArray.append(out_data[i]);
        }

        encryptedFile->write(outByteArray);

        if( cryptMode == ENCRYPT_GAMMA )
        {
            emit cryptCompteted(1);
        }
        else
        {
            emit cryptCompteted(0);
        }

    }

    emit progressChanged( 100 );

    sourceFile->close();

    delete sourceFile;

    encryptedFile->close();

    delete encryptedFile;

}

void threadWorker::setEncrypt( QFile* _encryptedFile, QFile* _sourceFile, gost12_15 *_gost12_15_Worker, cryptMode_t _cryptMode )
{
    encryptedFile = _encryptedFile;
    sourceFile    = _sourceFile;
    gost12_15_Worker = _gost12_15_Worker;
    cryptMode = _cryptMode;
}

void threadWorker::resume()
{
    sync.lock();
    pauseFlag = false;
    sync.unlock();
    pauseCond.wakeAll();
}

void threadWorker::pause()
{
    sync.lock();
    pauseFlag = true;
    sync.unlock();
}
