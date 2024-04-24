#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "gost12_15.h"
#include "threadworker.h"
#include <time.h>
#include <QFileDialog>
#include <QMessageBox>

#include <QDebug>
#include <QFile>

gost12_15 g;

threadWorker worker;

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    srand(time(NULL));
    ui->setupUi(this);


    connect(&worker, SIGNAL(progressChanged(int)), ui->progressBar_status, SLOT(setValue(int)));
    connect(&worker, SIGNAL(cryptCompteted(bool)), this, SLOT(encryptShow(bool)));

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

    QFile* sourceFile = new QFile(fileNamePath);

    if( !sourceFile->open(QIODevice::ReadOnly | QIODevice::Unbuffered) )
    {
        // Ошибка при открытии файла
        QMessageBox msgBox;
        msgBox.setWindowTitle("Decryptor");
        msgBox.setText("Ошибка при открытии файла, предназначенного для зашифрования!");
        msgBox.exec();
        sourceFile->close();
        delete sourceFile;
        return;
    }

    QByteArray sourceFileData = sourceFile->read(16000);

    ui->textEdit_source->clear();

    ui->textEdit_source->appendPlainText(QString(sourceFileData));

    ui->textEdit_sourceHEX->clear();

    ui->textEdit_sourceHEX->appendPlainText(QString(sourceFileData.toHex()));

    ui->textEdit_result->clear();
    ui->textEdit_resultHEX->clear();

    sourceFile->seek(0);

    QFile* encryptedFile = new QFile(fileNamePath+".crypt");

    if( !encryptedFile->open(QIODevice::WriteOnly|QIODevice::Truncate) )
    {
        // Ошибка при открытии файла

        QMessageBox msgBox;
        msgBox.setWindowTitle("Decryptor");
        msgBox.setText("Ошибка при открытии файла для зашифрованной информации!");
        msgBox.exec();
        sourceFile->close();
        encryptedFile->close();
        delete sourceFile;
        delete encryptedFile;
        return;
    }

    ui->pushButton_chooseFile->setEnabled(false);
    ui->pushButton_decrypt->setEnabled(false);
    ui->pushButton_encrypt->setEnabled(false);
    ui->pushButton_generationKey->setEnabled(false);
    ui->pushButton_setKey->setEnabled(false);
    ui->lineEdit_key->setEnabled(false);
    ui->progressBar_status->setEnabled(true);
    ui->lineEdit_sync->setEnabled(false);

    if(ui->radioButton_change->isChecked())
    {
        worker.setEncrypt( encryptedFile, sourceFile, &g, threadWorker::ENCRYPT_SIMPLE );
    }
    else if(ui->radioButton_gamma->isChecked())
    {
        worker.setEncrypt( encryptedFile, sourceFile, &g, threadWorker::ENCRYPT_GAMMA);
    }

    worker.start();

    ui->pushButton_pause->setEnabled(true);
    ui->pushButton_cancel->setEnabled(true);

}

/*
 * key - 12345, sync - 1,2,3,4,5,6,7,8
"Data before crypt: 1 2 3 4 5 6 7 8 9 a b c d e f 10 "
" Data after crypt: fc 69 2b 8b cd 8f e0 1a 60 f 56 1b a2 cf 4c 50 "
"Data after decrypt: 1 2 3 4 5 6 7 8 9 a b c d e f 10 "
*/
        /*
        vector<uint8_t> in_data = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x00,0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88};

        vector<uint8_t> out_data(16,0);

        vector<uint8_t> sync = {0x12,0x34,0x56,4,5,6,7,8};

        QString str = "Data before crypt: ";

        for(int i = 0; i < 16;i++)
        {
            str += QString::number( in_data[i], 16 ) + QString(" ");
        }

        qDebug() << str;

        str = " Data after crypt: ";

        out_data = g.gammaCryption(in_data,sync);

        for(int i = 0; i < 16;i++)
        {
            str += QString::number( out_data[i], 16 ) + QString(" ");
        }

        qDebug() << str;

        str = "Data after decrypt: ";

        out_data = g.gammaCryption(out_data,sync);

        for(int i = 0; i < 16;i++)
        {
            str += QString::number( out_data[i], 16 ) + QString(" ");
        }

        qDebug() << str;
*/

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

    QFile *sourceFile = new QFile(fileNamePath);

    if( !sourceFile->open(QIODevice::ReadOnly | QIODevice::Unbuffered) )
    {
        QMessageBox msgBox;
        msgBox.setWindowTitle("Decryptor");
        msgBox.setText("Ошибка при открытии зашифрованного файла");
        msgBox.exec();
        sourceFile->close();
        delete sourceFile;
        return;
    }

    if( (sourceFile->size() % 16 != 0) && ( ! ui->radioButton_gamma->isChecked() ) )
    {
        QMessageBox msgBox;
        msgBox.setWindowTitle("Decryptor");
        msgBox.setText("Зашифрованный файл поврежден, его размер не кратен 16 байтам!");
        msgBox.exec();
        sourceFile->close();
        delete sourceFile;
        return;
    }

    QByteArray sourceFileData = sourceFile->read(16000);

    ui->textEdit_source->clear();
    ui->textEdit_source->appendPlainText( QString(sourceFileData) );

    ui->textEdit_sourceHEX->clear();
    ui->textEdit_sourceHEX->appendPlainText(QString(sourceFileData.toHex()));

    ui->textEdit_result->clear();
    ui->textEdit_resultHEX->clear();

    sourceFile->seek(0);

    fileNamePath.chop(6);

    QFile* decryptedFile = new QFile (fileNamePath);

    if( !decryptedFile->open(QIODevice::WriteOnly|QIODevice::Truncate) )
    {
        QMessageBox msgBox;
        msgBox.setWindowTitle("Decryptor");
        msgBox.setText("Ошибка при открытии файла для расшифровки");
        msgBox.exec();
        sourceFile->close();
        decryptedFile->close();
        delete sourceFile;
        delete decryptedFile;
        return;
    }

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

    ui->pushButton_chooseFile->setEnabled(false);
    ui->pushButton_decrypt->setEnabled(false);
    ui->pushButton_encrypt->setEnabled(false);
    ui->pushButton_generationKey->setEnabled(false);
    ui->pushButton_setKey->setEnabled(false);
    ui->lineEdit_key->setEnabled(false);
    ui->progressBar_status->setEnabled(true);
    ui->lineEdit_sync->setEnabled(false);

    if(ui->radioButton_change->isChecked())
    {
        worker.setEncrypt( decryptedFile, sourceFile, &g, threadWorker::DECRYPT_SIMPLE );
    }
    else if(ui->radioButton_gamma->isChecked())
    {
        worker.setEncrypt( decryptedFile, sourceFile, &g, threadWorker::DECRYPT_GAMMA );
    }

    worker.start();

    ui->pushButton_pause->setEnabled(true);
    ui->pushButton_cancel->setEnabled(true);

    // worker.quit();

}


void MainWindow::on_pushButton_setKey_clicked()
{       
    ui->pushButton_generationKey->setEnabled(false);

   if(ui->lineEdit_key->text().isEmpty())
   {
       QMessageBox msgBox;
       msgBox.setWindowTitle("Decryptor");
       msgBox.setText("Заполните поле ключа!");
       msgBox.exec();
       ui->pushButton_generationKey->setEnabled(true);
       return;
   }

   if(ui->lineEdit_sync->text().isEmpty() && ui->radioButton_gamma->isChecked())
   {
       QMessageBox msgBox;
       msgBox.setWindowTitle("Decryptor");
       msgBox.setText("Заполните поле синхропосылки!");
       msgBox.exec();
       ui->pushButton_generationKey->setEnabled(true);
       return;
   }

   if( ui->pushButton_setKey->text() == "Сбросить" )
   {
       if(ui->radioButton_gamma->isChecked())
       {
           ui->lineEdit_sync->clear();
           ui->lineEdit_sync->setStyleSheet("QLineEdit { background: rgb(255, 255, 255); selection-background-color: rgb(0, 0, 255); }");
           g.clearSync();
       }
       ui->lineEdit_key->clear();
       ui->lineEdit_key->setStyleSheet("QLineEdit { background: rgb(255, 255, 255); selection-background-color: rgb(0, 0, 255); }");
       ui->pushButton_setKey->setText("Задать");
       ui->progressBar_status->setValue( 0 );
       ui->pushButton_generationKey->setEnabled(true);
       g.clearKey();
   }
   else
   {
       if(ui->radioButton_gamma->isChecked())
       {
           ui->lineEdit_sync->setStyleSheet("QLineEdit { background: rgb(0, 255, 255); selection-background-color: rgb(0, 0, 255); }");

           if(ui->checkBox_hex->isChecked())
           {

           }
           g.setSync(ui->lineEdit_sync->text().toStdString().c_str());
       }

       ui->lineEdit_key->setStyleSheet("QLineEdit { background: rgb(0, 255, 255); selection-background-color: rgb(0, 0, 255); }");
       ui->pushButton_setKey->setText("Сбросить");

       if(ui->checkBox_hex->isChecked())
       {

       }
       g.setKey( ui->lineEdit_key->text().toStdString().c_str() );
   }
}


void MainWindow::on_pushButton_generationKey_clicked()
{

    const char *acsciiSymbolsForRandomKey = "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM:<>'\".,|?;\\/[]{}-=!@#$%^&*()_+~";

    const char *hexSymbolsForRandomKey = "1234567890ABCDEF";

    const char* symbolsForRandomKey = 0;

    if( ui->checkBox_hex->isChecked() )
    {
        symbolsForRandomKey = hexSymbolsForRandomKey;
    }
    else
    {
        symbolsForRandomKey = acsciiSymbolsForRandomKey;
    }


    QString generation_key;
    QString generation_sync;

    for(int i = 0; i < ui->spinBox_keyLength->value(); i++)
    {
            generation_key += symbolsForRandomKey[ rand() % strlen(symbolsForRandomKey) ];
    }

    if(ui->radioButton_gamma->isChecked())
    {
        uint8_t min = 1;
        uint8_t max = 9;
        for(int i = 0; i < ( rand() % (max - min + 1) + min); i++)
        {
            generation_sync += symbolsForRandomKey [rand() % strlen(symbolsForRandomKey)];
        }
    }

    ui->lineEdit_sync->setText(generation_sync);
    ui->lineEdit_key->setText(generation_key);

}

void MainWindow::encryptShow(bool isEncrypt)
{

    ui->pushButton_chooseFile->setEnabled(true);
    ui->pushButton_decrypt->setEnabled(true);
    ui->pushButton_encrypt->setEnabled(true);
    ui->pushButton_generationKey->setEnabled(true);
    ui->pushButton_setKey->setEnabled(true);
    ui->lineEdit_key->setEnabled(true);
    ui->progressBar_status->setEnabled(false);
    ui->lineEdit_sync->setEnabled(true);

    ui->pushButton_pause->setEnabled(false);
    ui->pushButton_cancel->setEnabled(false);

    QMessageBox msgBox;

    msgBox.setWindowTitle("Decryptor");

    QString filenamePath;

    if( isEncrypt )
    {
        filenamePath = ui->lineEdit_inputFile->text()+".crypt";

        ui->pushButton_generationKey->setEnabled(false);

        msgBox.setText("Шифрование файла завершено!");

    }
    else
    {

        filenamePath = ui->lineEdit_inputFile->text();

        filenamePath.chop(6);

        ui->pushButton_generationKey->setEnabled(false);

        msgBox.setText("Дешифрование файла завершено!");


    }

    msgBox.exec();

    QFile file(filenamePath);

    if( !file.open(QIODevice::ReadOnly | QIODevice::Unbuffered) )
    {
        return;
    }

    QByteArray sourceFileData = file.read(16000);

    ui->textEdit_result->setText( QString::fromUtf8(sourceFileData) );
    ui->textEdit_resultHEX->setText(QString(sourceFileData.toHex()));

}


void MainWindow::on_pushButton_pause_clicked()
{

    if( ui->pushButton_pause->text() == "Пауза" )
    {
        worker.pause();
        ui->pushButton_pause->setText("Продолжить");
    }
    else
    {
        worker.resume();
        ui->pushButton_pause->setText("Пауза");
    }

}

void MainWindow::on_pushButton_cancel_clicked()
{

    // worker.quit();
    // worker.blockSignals(true);
    worker.terminate();
    worker.wait();

    ui->pushButton_chooseFile->setEnabled(true);
    ui->pushButton_decrypt->setEnabled(true);
    ui->pushButton_encrypt->setEnabled(true);
    ui->pushButton_generationKey->setEnabled(true);
    ui->pushButton_setKey->setEnabled(true);
    ui->lineEdit_key->setEnabled(true);

    ui->pushButton_pause->setEnabled(false);
    ui->pushButton_cancel->setEnabled(false);

    ui->progressBar_status->setValue(0);
    ui->progressBar_status->setEnabled(false);

}

void MainWindow::on_radioButton_change_clicked()
{
    if(ui->radioButton_change->isChecked())
    {
       ui->lineEdit_sync->setStyleSheet("QLineEdit { background: rgb(255, 255, 255); selection-background-color: rgb(0, 0, 255); }");
       ui->lineEdit_sync->clear();
       ui->lineEdit_sync->setEnabled(false);
       ui->label_sync->setEnabled(false);
       g.clearSync();
    }
}

void MainWindow::on_radioButton_gamma_clicked()
{
    if(ui->radioButton_gamma->isChecked())
    {
        ui->lineEdit_sync->setEnabled(true);
        ui->label_sync->setEnabled(true);
    }
}

