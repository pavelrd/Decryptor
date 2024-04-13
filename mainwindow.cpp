#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "gost12_15.h"
#include <QFileDialog>
#include <QMessageBox>

#include <QDebug>
#include <QFile>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}


void MainWindow::on_pushButton_chooseFile_clicked()
{

    QString fileNamePath = QFileDialog::getOpenFileName(0, "Выбор файла" );

    ui->lineEdit_inputFile->setText(fileNamePath);

}


void MainWindow::on_pushButton_encrypt_clicked()
{

    QString fileNamePath = ui->lineEdit_inputFile->text();

    QFile file(fileNamePath);

    if( !file.open(QIODevice::ReadOnly | QIODevice::Unbuffered) )
    {
        // Ошибка при открытии файла
        QMessageBox msgBox;
        msgBox.setText("Ошибка при открытии файла, предназначенного для зашифрования!");
        msgBox.exec();
        return;
    }

    QByteArray fileBytearray = file.readAll();

    file.close();

    QFile encryptedFile(fileNamePath+".crypt");

    if( !encryptedFile.open(QIODevice::WriteOnly|QIODevice::Truncate) )
    {
        // Ошибка при открытии файла

        QMessageBox msgBox;
        msgBox.setText("Ошибка при открытии файла для зашифрованной информации!");
        msgBox.exec();

        return;
    }

    uint8_t block[16] = {0};
    uint8_t encryptedBlock[16] = {0};

    // ------- Запись длины файла в начало первого блока, который будет зашифрован

    uint32_t value = fileBytearray.length();

    block[0] = value & 0xFF;

    block[1] = ( value >> 8 ) & 0xFF;

    block[2] = ( value >> 16 ) & 0xFF;

    block[3] = ( value >> 24 ) & 0xFF;

    // -------

    uint32_t j = 4; // Начинаем запись файла с 5 байта блока, так как в первые 4 байта записан размер файла

    gost12_15* g = new gost12_15();

    QString key = ui->lineEdit_key->text();

    g->setKey(key.toStdString().c_str());

    for( uint32_t i = 0 ; i < fileBytearray.length(); i++ )
    {

        block[j] = fileBytearray.at(i);

        j++;

        if( j >= 16 )
        {

            j = 0;

            g->encrypt(encryptedBlock, block);

            encryptedFile.write((const char*)encryptedBlock, 16);

            for( uint32_t indexClear = 0 ; indexClear < 16; indexClear++)
            {
                block[indexClear] = 0x00;
            }

        }

    }

    if( j != 0 )
    {

        g->encrypt(encryptedBlock, block);

        encryptedFile.write((const char*)encryptedBlock, 16);

    }

    delete g;

    encryptedFile.close();

}


void MainWindow::on_pushButton_decrypt_clicked()
{

    QString fileNamePath = ui->lineEdit_inputFile->text();

    QFile file(fileNamePath);

    if( !file.open(QIODevice::ReadOnly | QIODevice::Unbuffered) )
    {
        QMessageBox msgBox;
        msgBox.setText("Ошибка при открытии зашифрованного файла");
        msgBox.exec();
        return;
    }

    QByteArray fileBytearray = file.readAll();

    file.close();

    if( fileBytearray.size() % 16 != 0 )
    {
        QMessageBox msgBox;
        msgBox.setText("Зашифроанный файл поврежден, его размер не кратен 16 байтам!");
        msgBox.exec();
        return;
    }

    fileNamePath.chop(6);

    QFile decryptedFile(fileNamePath);


    if( !decryptedFile.open(QIODevice::WriteOnly|QIODevice::Truncate) )
    {
        QMessageBox msgBox;
        msgBox.setText("Ошибка при открытии файла для расшифровки");
        msgBox.exec();
        return;
    }

    uint8_t block[16] = {0};
    uint8_t decryptedBlock[16] = {0};

    uint32_t j = 0;
    uint32_t fileSize = 0;
    uint32_t fileCounter = 0;

    gost12_15* g = new gost12_15();

    QString key = ui->lineEdit_key->text();

    g->setKey(key.toStdString().c_str());

    for( uint32_t i = 0 ; i < fileBytearray.length(); i++ )
    {

        block[j] = fileBytearray.at(i);

        j++;

        if( j >= 16 )
        {

            j = 0;
            qDebug() << "BLOCK-";
            for( auto elem : block)
            {
                qDebug() << hex <<elem << " ";
            }
            g->decrypt(decryptedBlock, block);
            qDebug() << "DECBLOCK-";
            for( auto elem : decryptedBlock)
            {
                qDebug() << hex <<elem << " ";
            }
            qDebug();
            if( i < 16 )
            {

                // Первый блок, в нем первые 4 байта это длина файла, запоминаем эту длин

                fileSize |= decryptedBlock[0];
                fileSize |= ( ( (uint32_t) decryptedBlock[1] ) << 8 );
                fileSize |= ( ( (uint32_t) decryptedBlock[2] ) << 16 );
                fileSize |= ( ( (uint32_t) decryptedBlock[3] ) << 24 );

                if( fileSize < 12 ) // Файл полностью помещается в первом блоке. Чтобы это условие было выполнено файл должен быть размера 16 - 4 = 12
                {
                    decryptedFile.write( (const char*) decryptedBlock + 4, fileSize );
                    break;
                }
                else // Файл не помещается в одном блоке, запись уже считанной на текущий момент части файла.
                {
                   decryptedFile.write( (const char*) decryptedBlock + 4, 12 );
                   fileCounter += 12;
                }

            }
            else
            {

                // Второй и последующий блоки

                if( (fileCounter + 16) < fileSize )
                {
                    decryptedFile.write((const char*)decryptedBlock, 16);
                    fileCounter += 16;
                }
                else
                {
                    decryptedFile.write((const char*)decryptedBlock, fileSize - fileCounter);
                }

            }

            for( uint32_t indexClear = 0 ; indexClear < 16; indexClear++)
            {
                block[indexClear] = 0x00;
            }

        }

    }

    delete g;

    decryptedFile.close();

}


void MainWindow::on_pushButton_setKey_clicked()
{

   // QString key = ui->lineEdit_key->text();

   // g.setKey(key.toStdString().c_str());

   // keySetted = true;

}

