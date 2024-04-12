#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "gost12_15.h"
#include <QFileDialog>

#include <QDebug>
#include <QFile>

gost12_15 g;

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
        return;
    }

    QByteArray fileBytearray = file.readAll();

    file.close();

    QFile encryptedFile(fileNamePath+".crypt");

    if( !encryptedFile.open(QIODevice::WriteOnly|QIODevice::Truncate) )
    {
        // Ошибка при открытии файла
        return;
    }

    uint8_t block[16] = {0};
    uint8_t encryptedBlock[16] = {0};

    uint32_t j = 0;

    for( uint32_t i = 0 ; i < fileBytearray.length(); i++ )
    {

        block[j] = fileBytearray.at(i);

        j++;

        if( j >= 16 )
        {

            j = 0;

            g.encrypt(encryptedBlock, block);

            encryptedFile.write((const char*)encryptedBlock, 16);

            for( uint32_t indexClear = 0 ; indexClear < 16; indexClear++)
            {
                block[indexClear] = 0x00;
            }

        }

    }

    if( j != 0 )
    {

        g.encrypt(encryptedBlock, block);

        encryptedFile.write((const char*)encryptedBlock, 16);

    }

    encryptedFile.close();

}


void MainWindow::on_pushButton_decrypt_clicked()
{

    QString fileNamePath = ui->lineEdit_inputFile->text();

    QFile file(fileNamePath);

    if( !file.open(QIODevice::ReadOnly | QIODevice::Unbuffered) )
    {
        // Ошибка при открытии файла
        return;
    }

    QByteArray fileBytearray = file.readAll();

    file.close();

    fileNamePath.chop(6);

    QFile decryptedFile(fileNamePath);

    if( !decryptedFile.open(QIODevice::WriteOnly|QIODevice::Truncate) )
    {
        // Ошибка при открытии файла
        return;
    }

    uint8_t block[16] = {0};
    uint8_t decryptedBlock[16] = {0};

    uint32_t j = 0;

    for( uint32_t i = 0 ; i < fileBytearray.length(); i++ )
    {

        block[j] = fileBytearray.at(i);

        j++;

        if( j >= 16 )
        {

            j = 0;

            g.decrypt(decryptedBlock, block);

            decryptedFile.write((const char*)decryptedBlock, 16);

            for( uint32_t indexClear = 0 ; indexClear < 16; indexClear++)
            {
                block[indexClear] = 0x00;
            }

        }

    }

    if( j != 0 )
    {

        g.decrypt(decryptedBlock, block);

        decryptedFile.write((const char*)decryptedBlock, 16);

    }

    decryptedFile.close();
}


void MainWindow::on_pushButton_setKey_clicked()
{

    QString key = ui->lineEdit_key->text();

    g.setKey(key.toStdString().c_str());

}

