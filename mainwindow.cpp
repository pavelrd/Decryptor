#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "gost12_15.h"
#include "threadworker.h"
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

    worker.setEncrypt( encryptedFile, sourceFile, &g, true );

    worker.start();

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

    worker.setEncrypt( decryptedFile, sourceFile, &g, false );

    worker.start();

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

    QMessageBox msgBox;

    msgBox.setWindowTitle("Decryptor");

    if( isEncrypt )
    {
        msgBox.setText("Шифрование файла завершено!");
    }
    else
    {
         msgBox.setText("Дешифрование файла завершено!");
    }

    msgBox.exec();
}

