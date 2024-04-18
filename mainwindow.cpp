#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "gost12_15.h"
#include <QFileDialog>
#include <QMessageBox>

#include <QDebug>
#include <QFile>

gost12_15 g;

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    srand(time(NULL));
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
    if( !g.isKeySetted() )
    {
        QMessageBox msgBox;
        msgBox.setWindowTitle("Decryptor");
        msgBox.setText("Не задан ключ!");
        msgBox.exec();
        return;
    }

    QString fileNamePath = ui->lineEdit_inputFile->text();

    QFile file(fileNamePath);

    if( !file.open(QIODevice::ReadOnly | QIODevice::Unbuffered) )
    {
        // Ошибка при открытии файла
        QMessageBox msgBox;
        msgBox.setWindowTitle("Decryptor");
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

    ui->progressBar_status->setEnabled(true);

    ui->progressBar_status->setValue(0);

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

            ui->progressBar_status->setValue( ((double)i) / fileBytearray.length() * 100 );

        }

    }

    if( j != 0 )
    {

        g.encrypt(encryptedBlock, block);

        encryptedFile.write((const char*)encryptedBlock, 16);

    }

    ui->progressBar_status->setValue( 100 );

    QMessageBox msgBox;
    msgBox.setWindowTitle("Decryptor");
    msgBox.setText("Шифрование файла завершено!");
    msgBox.exec();

    ui->progressBar_status->setEnabled(false);

    encryptedFile.close();

}


void MainWindow::on_pushButton_decrypt_clicked()
{
    if( !g.isKeySetted() )
    {
        QMessageBox msgBox;
        msgBox.setWindowTitle("Decryptor");
        msgBox.setText("Не задан ключ!");
        msgBox.exec();
        return;
    }


    QString fileNamePath = ui->lineEdit_inputFile->text();

    QFile file(fileNamePath);

    if( !file.open(QIODevice::ReadOnly | QIODevice::Unbuffered) )
    {
        QMessageBox msgBox;
        msgBox.setWindowTitle("Decryptor");
        msgBox.setText("Ошибка при открытии зашифрованного файла");
        msgBox.exec();
        return;
    }

    QByteArray fileBytearray = file.readAll();

    file.close();

    if( fileBytearray.size() % 16 != 0 )
    {
        QMessageBox msgBox;
        msgBox.setWindowTitle("Decryptor");
        msgBox.setText("Зашифрованный файл поврежден, его размер не кратен 16 байтам!");
        msgBox.exec();
        return;
    }

    fileNamePath.chop(6);

    QFile decryptedFile(fileNamePath);


    if( !decryptedFile.open(QIODevice::WriteOnly|QIODevice::Truncate) )
    {
        QMessageBox msgBox;
        msgBox.setWindowTitle("Decryptor");
        msgBox.setText("Ошибка при открытии файла для расшифровки");
        msgBox.exec();
        return;
    }

    uint8_t block[16] = {0};
    uint8_t decryptedBlock[16] = {0};

    uint32_t j = 0;
    uint32_t fileSize = 0;
    uint32_t fileCounter = 0;

    ui->progressBar_status->setEnabled(true);

    for( uint32_t i = 0 ; i < fileBytearray.length(); i++ )
    {

        block[j] = fileBytearray.at(i);

        j++;

        if( j >= 16 )
        {

            j = 0;

            g.decrypt(decryptedBlock, block);

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

            ui->progressBar_status->setValue( ((double)i) / fileBytearray.length() * 100 );

        }

    }

    decryptedFile.close();

    ui->progressBar_status->setValue( 100 );


    /*
    QString str = "Дешифрование файла завершено!";

    int spacesNum = ( ui->statusbar->size().width() - (str.length()/2) ) / 2;

    QString str2;

    if(spacesNum > 1 )
    {

        for( int i = 0 ; i < spacesNum; i++ )
        {
            str2 += " ";
        }

    }

    str2 += str;

    ui->statusbar->showMessage(str2, 10000);

    QLabel* statusLabel = new QLabel("Дешифрование файла завершено!");
    statusBar()->addWidget(statusLabel,1);
    */

    QMessageBox msgBox;
    msgBox.setWindowTitle("Decryptor");
    msgBox.setText("Дешифрование файла завершено!");
    msgBox.exec();


    ui->progressBar_status->setEnabled(false);

}


void MainWindow::on_pushButton_setKey_clicked()
{

   QString key = ui->lineEdit_key->text();

   static bool keySetted = 1;

   if(ui->lineEdit_key->text().isEmpty())
   {
       QMessageBox msgBox;
       msgBox.setWindowTitle("Decryptor");
       msgBox.setText("Заполните поле ключа!");
       msgBox.exec();
       return;
   }

   if(keySetted == 0)
   {
       key.clear();
       ui->lineEdit_key->clear();
       ui->lineEdit_key->setStyleSheet("QLineEdit { background: rgb(255, 255, 255); selection-background-color: rgb(0, 0, 255); }");
       ui->pushButton_setKey->setText("Задать");
       keySetted = 1;
       ui->progressBar_status->setValue( 0 );
   }
   else
   {
       ui->lineEdit_key->setStyleSheet("QLineEdit { background: rgb(0, 255, 255); selection-background-color: rgb(0, 0, 255); }");
       ui->pushButton_setKey->setText("Сбросить");
       keySetted = 0;
   }

   g.setKey(key.toStdString().c_str());

}

const char *symbolsForRandomKey = "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM:<>'\".,|?;\\/[]{}-=!@#$%^&*()_+~";

void MainWindow::on_pushButton_generationKey_clicked()
{

    QString generation_key;

    for(int i = 0; i < ui->spinBox_keyLength->value(); i++)
    {
            generation_key += symbolsForRandomKey[ rand() % strlen(symbolsForRandomKey) ];
    }

    ui->lineEdit_key->setText(generation_key);

}

