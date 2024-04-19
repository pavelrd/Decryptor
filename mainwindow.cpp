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

    worker.setEncrypt( encryptedFile, sourceFile, &g, true );

    worker.start();

    ui->pushButton_pause->setEnabled(true);
    ui->pushButton_cancel->setEnabled(true);

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

    QFile *sourceFile = new QFile(fileNamePath);

    if( !sourceFile->open(QIODevice::ReadOnly | QIODevice::Unbuffered) )
    {
        QMessageBox msgBox;
        msgBox.setWindowTitle("Decryptor");
        msgBox.setText("Ошибка при открытии зашифрованного файла");
        msgBox.exec();
        delete sourceFile;
        return;
    }

    if( sourceFile->size() % 16 != 0 )
    {
        QMessageBox msgBox;
        msgBox.setWindowTitle("Decryptor");
        msgBox.setText("Зашифрованный файл поврежден, его размер не кратен 16 байтам!");
        msgBox.exec();
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

    worker.setEncrypt( decryptedFile, sourceFile, &g, false );

    worker.start();

    ui->pushButton_pause->setEnabled(true);
    ui->pushButton_cancel->setEnabled(true);

    // worker.quit();

}


void MainWindow::on_pushButton_setKey_clicked()
{

   if(ui->lineEdit_key->text().isEmpty())
   {
       QMessageBox msgBox;
       msgBox.setWindowTitle("Decryptor");
       msgBox.setText("Заполните поле ключа!");
       msgBox.exec();
       return;
   }

   if( ui->pushButton_setKey->text() == "Сбросить" )
   {
       ui->lineEdit_key->clear();
       ui->lineEdit_key->setStyleSheet("QLineEdit { background: rgb(255, 255, 255); selection-background-color: rgb(0, 0, 255); }");
       ui->pushButton_setKey->setText("Задать");
       ui->progressBar_status->setValue( 0 );
       g.clearKey();
   }
   else
   {
       ui->lineEdit_key->setStyleSheet("QLineEdit { background: rgb(0, 255, 255); selection-background-color: rgb(0, 0, 255); }");
       ui->pushButton_setKey->setText("Сбросить");
       g.setKey( ui->lineEdit_key->text().toStdString().c_str() );
   }



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

void MainWindow::encryptShow(bool isEncrypt)
{

    ui->pushButton_chooseFile->setEnabled(true);
    ui->pushButton_decrypt->setEnabled(true);
    ui->pushButton_encrypt->setEnabled(true);
    ui->pushButton_generationKey->setEnabled(true);
    ui->pushButton_setKey->setEnabled(true);
    ui->lineEdit_key->setEnabled(true);
    ui->progressBar_status->setEnabled(false);

    ui->pushButton_pause->setEnabled(false);
    ui->pushButton_cancel->setEnabled(false);

    QMessageBox msgBox;

    msgBox.setWindowTitle("Decryptor");

    QString filenamePath;

    if( isEncrypt )
    {
        filenamePath = ui->lineEdit_inputFile->text()+".crypt";
        msgBox.setText("Шифрование файла завершено!");

    }
    else
    {

        filenamePath = ui->lineEdit_inputFile->text();

        filenamePath.chop(6);

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

