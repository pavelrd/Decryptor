#include "threadworker.h"
#include <QDebug>
#include <QByteArray>
#include <QMessageBox>

void threadWorker::run()
{

    // qDebug() << isHeaderPresent << " " << sourceFileSize;

    if( cryptMode == ENCRYPT_SIMPLE )
    {

        uint8_t block[blockSize] = {0};
        uint8_t encryptedBlock[blockSize] = {0};

        qint64 currentReadedBytes = 0;

        qint64 bytesReadTotal = 0;

        bytesReadTotal += currentReadedBytes;

        if(isHeaderPresent)
        {
            // ------- Запись длины файла в начало первого блока, который будет зашифрован

            uint32_t value = sourceFile->size();

            block[0] = value & 0xFF;

            block[1] = ( value >> 8 ) & 0xFF;

            block[2] = ( value >> 16 ) & 0xFF;

            block[3] = ( value >> 24 ) & 0xFF;

            // -------

            currentReadedBytes   += 4;

            // Начинаем запись файла с 5 байта блока, так как в первые 4 байта записан размер файла

            currentReadedBytes += sourceFile->read( (char*) block + 4, blockSize - 4 );

            bytesReadTotal = currentReadedBytes - 4;

        }
        else
        {

            currentReadedBytes += sourceFile->read( (char*) block, blockSize );

            bytesReadTotal = currentReadedBytes;

        }

        int progressValue = 0;

        emit progressChanged(0);

        do
        {

            if( currentReadedBytes >= blockSize )
            {

                sync.lock();

                if(pauseFlag)
                {
                    pauseCond.wait(&sync); // in this place, your thread will stop to execute until someone calls resume
                }

                sync.unlock();

                gost12_15_Worker->encrypt(encryptedBlock, block);

                encryptedFile->write((const char*)encryptedBlock, blockSize);

                int currentProgressValue = ( (int) ( ((double)bytesReadTotal) / sourceFileSize * 100 ) );

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

                for( int i = currentReadedBytes; i < blockSize; i++)
                {
                    block[i] = 0x00;
                }

                gost12_15_Worker->encrypt(encryptedBlock, block);

                encryptedFile->write((const char*)encryptedBlock, blockSize);

                break;

            }

            currentReadedBytes = sourceFile->read( (char*)block, sourceFileSize - bytesReadTotal >= blockSize ? blockSize : sourceFileSize - bytesReadTotal );

            bytesReadTotal += currentReadedBytes;

        } while( currentReadedBytes > 0 );

        encryptedFile->flush();

        emit cryptCompteted(1);

    }
    else if( cryptMode == DECRYPT_SIMPLE )
    {

        uint8_t block[blockSize] = {0};

        uint32_t fileSize = 0;
        uint32_t fileCounter = 0;

        int currentReadedBytes = 0;
        int progressValue = 0;
        uint32_t bytesReadTotal = 0;

        // Начинаем запись файла с 5 байта блока, так как в первые 4 байта записан размер файла

        while( 1 )
        {

            sync.lock();
            if(pauseFlag)
            {
                pauseCond.wait(&sync); // in this place, your thread will stop to execute until someone calls resume
            }
            sync.unlock();

            currentReadedBytes = sourceFile->read( (char*)block, 16 );
            bytesReadTotal    += currentReadedBytes;

            if( currentReadedBytes <= 0 )
            {
                break;
            }

            uint8_t decryptedBlock[blockSize];

            gost12_15_Worker->decrypt(decryptedBlock, block);

            if( isHeaderPresent && ( bytesReadTotal <= blockSize ) )
            {

                // Первый блок, в нем первые 4 байта это длина файла, запоминаем эту длин

                fileSize |= decryptedBlock[0];
                fileSize |= ( ( (uint32_t) decryptedBlock[1] ) << 8 );
                fileSize |= ( ( (uint32_t) decryptedBlock[2] ) << 16 );
                fileSize |= ( ( (uint32_t) decryptedBlock[3] ) << 24 );

                if( fileSize < (blockSize - 4) ) // Файл полностью помещается в первом блоке.
                {
                    encryptedFile->write( (const char*) decryptedBlock + 4, fileSize );
                    break;
                }
                else // Файл не помещается в одном блоке, запись уже считанной на текущий момент части файла.
                {
                   encryptedFile->write( (const char*) decryptedBlock + 4, blockSize - 4 );
                   fileCounter += blockSize - 4;
                }

            }
            else
            {

                // Второй и последующий блоки

                if( (fileCounter + blockSize) < fileSize )
                {
                    encryptedFile->write((const char*)decryptedBlock, blockSize);
                    fileCounter += blockSize;
                }
                else
                {
                    encryptedFile->write((const char*)decryptedBlock, fileSize - fileCounter);
                }

            }

            int currentProgressValue = ( (int) ( ((double) sourceFile->pos()) / sourceFileSize * 100 ) );

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

        uint8_t in_buffer[blockSize];
        uint8_t out_buffer[blockSize];

        int progressValue = 0;

        gost12_15_Worker->gammaCryptionStart();

        while( 1 )
        {

            int readedBytes = sourceFile->read( (char*) in_buffer, blockSize );

            if( readedBytes == 0 )
            {
                break;
            }

            gost12_15_Worker->gammaCryption( out_buffer, in_buffer, readedBytes );

            encryptedFile->write( (char*)out_buffer, readedBytes );

            int currentProgressValue = ( (int) ( ((double) sourceFile->pos()) / sourceFile->size() * 100 ) );

            if( progressValue < currentProgressValue )
            {
                progressValue = currentProgressValue;
                emit progressChanged(progressValue);
            }

        }

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

}

void threadWorker::setEncrypt( QFile* _encryptedFile, QFile* _sourceFile, quint64 _sourceFileSize, bool _isHeaderPresent, gost12_15 *_gost12_15_Worker, cryptMode_t _cryptMode )
{
    encryptedFile    = _encryptedFile;
    sourceFile       = _sourceFile;
    sourceFileSize   = _sourceFileSize;
    gost12_15_Worker = _gost12_15_Worker;
    cryptMode        = _cryptMode;
    isHeaderPresent  = _isHeaderPresent;

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
