#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "gost12_15.h"
#include "threadworker.h"
#include <time.h>
#include <QFileDialog>
#include <QMessageBox>

#include <QDebug>
#include <QFile>

#define BLOCK_SIZE       16
#define MAX_THREAD_COUNT 16
#define CRYPT_FILE_HEADER_LENGTH    4

gost12_15 g[MAX_THREAD_COUNT];

threadWorker worker[MAX_THREAD_COUNT];

QFile* sourceFiles[MAX_THREAD_COUNT]    = {0};
QFile* encryptedFiles[MAX_THREAD_COUNT] = {0};

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    srand(time(NULL));
    ui->setupUi(this);

    int idealThreads = QThread::idealThreadCount();

    ui->spinBox_threadCount->setValue( idealThreads > 16 ? 16 : idealThreads  );

    for(int i = 0 ; i < MAX_THREAD_COUNT; i++)
    {
        connect(&worker[i], SIGNAL(progressChanged(int)), ui->progressBar_status, SLOT(setValue(int)));
        connect(&worker[i], SIGNAL(cryptCompteted(bool)), this, SLOT(encryptShow(bool)));
    }

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

    disable_elements_before_crypt();

    if( ! ( g[0].isKeySetted() ) )
    {
        QMessageBox msgBox;
        msgBox.setWindowTitle("Decryptor");
        msgBox.setText("Не задан ключ!");
        msgBox.exec();
        enable_elements_after_crypt();
        return;
    }

    QString fileNamePath = ui->lineEdit_inputFile->text();

    sourceFiles[0] = new QFile(fileNamePath);

    if( !openFile( sourceFiles[0], QIODevice::ReadOnly, "Ошибка при открытии файла, предназначенного для зашифрования!" ) )
    {
        delete sourceFiles[0];
        enable_elements_after_crypt();
        return;
    }

    QByteArray sourceFileData = sourceFiles[0]->read(16000);

    ui->textEdit_source->clear();

    ui->textEdit_source->appendPlainText(QString(sourceFileData));

    ui->textEdit_sourceHEX->clear();

    ui->textEdit_sourceHEX->appendPlainText(QString(sourceFileData.toHex()));

    ui->textEdit_result->clear();
    ui->textEdit_resultHEX->clear();

    sourceFiles[0]->seek(0);

    encryptedFiles[0] = new QFile(fileNamePath+".crypt");

    encryptedFiles[0]->resize(0);

    if( !openFile(encryptedFiles[0], QIODevice::WriteOnly, "Ошибка при открытии файла для зашифрованной информации!") )
    {
        sourceFiles[0]->close();
        delete sourceFiles[0];
        delete encryptedFiles[0];
        enable_elements_after_crypt();
        return;
    }

    if(ui->radioButton_change->isChecked())
    {

        int threadCount = ui->spinBox_threadCount->value();

        if( ( sourceFiles[0]->size() < 65535 ) || ( threadCount <= 1 ) )
        {

            worker[0].setEncrypt( encryptedFiles[0], sourceFiles[0], sourceFiles[0]->size(), true, &(g[0]), threadWorker::ENCRYPT_SIMPLE );

            worker[0].start();

        }
        else
        {

            qint64 fullSize = sourceFiles[0]->size();

            quint64 partSize = ( ( fullSize / BLOCK_SIZE ) / threadCount ) * BLOCK_SIZE; // 12345 / 16 / 4 = 192 * 16 = 3072

            encryptedFiles[0]->seek(0);

            worker[0].setEncrypt( encryptedFiles[0], sourceFiles[0], partSize - CRYPT_FILE_HEADER_LENGTH, true, &(g[0]), threadWorker::ENCRYPT_SIMPLE );

            for( int i = 1 ; ( i < threadCount ) && ( i < MAX_THREAD_COUNT ); i++ )
            {

                sourceFiles[i]    = new QFile(fileNamePath);
                encryptedFiles[i] = new QFile(fileNamePath + QString(".crypt"));

                if( !openFile(sourceFiles[i], QIODevice::ReadOnly, "Ошибка при повторном открытии исходного файла! Повторное открытие файла нужно для многопоточного шифрования.") )
                {
                    return;
                }

                if( !openFile(encryptedFiles[i], QIODevice::WriteOnly, "Ошибка при открытии одного из временных выходных файлов!") )
                {
                    return;
                }

                volatile uint32_t chunkSize = ( i < (threadCount - 1) ) ? partSize : fullSize - ( ( partSize * i ) - CRYPT_FILE_HEADER_LENGTH);

                sourceFiles[i]->seek( (partSize * i) - CRYPT_FILE_HEADER_LENGTH );

                encryptedFiles[i]->seek( partSize * i );

                worker[i].setEncrypt( encryptedFiles[i],
                                      sourceFiles[i],
                                      chunkSize,
                                      false,
                                      &(g[i]),
                                      threadWorker::ENCRYPT_SIMPLE );

            }

            workerCompteteCounter = 0;

            for( int i = 0 ; i < threadCount; i++ )
            {
                worker[i].start();
            }

        }

    }
    else if(ui->radioButton_gamma->isChecked())
    {

        worker[0].setEncrypt( encryptedFiles[0], sourceFiles[0], sourceFiles[0]->size(), true, &(g[0]), threadWorker::ENCRYPT_GAMMA);

        worker[0].start();

    }

    ui->pushButton_pause->setEnabled(true);
    ui->pushButton_cancel->setEnabled(true);
    ui->progressBar_status->setEnabled(true);

}

void MainWindow::on_pushButton_decrypt_clicked()
{

    disable_elements_before_crypt();

    if( ! (g[0].isKeySetted()) )
    {
        QMessageBox msgBox;
        msgBox.setWindowTitle("Decryptor");
        msgBox.setText("Не задан ключ!");
        msgBox.exec();
        enable_elements_after_crypt();
        return;
    }


    QString fileNamePath = ui->lineEdit_inputFile->text();

    sourceFiles[0] = new QFile(fileNamePath);

    if( !openFile(sourceFiles[0], QIODevice::ReadOnly, "Ошибка при открытии зашифрованного файла" ) )
    {
        delete sourceFiles[0];
        enable_elements_after_crypt();
        return;
    }

    if( (sourceFiles[0]->size() % BLOCK_SIZE != 0) && ( ! ui->radioButton_gamma->isChecked() ) )
    {
        QMessageBox msgBox;
        msgBox.setWindowTitle("Decryptor");
        msgBox.setText("Зашифрованный файл поврежден, его размер не кратен "+QString::number(BLOCK_SIZE)+" байтам!");
        msgBox.exec();
        sourceFiles[0]->close();
        delete sourceFiles[0];
        enable_elements_after_crypt();
        return;
    }

    QByteArray sourceFileData = sourceFiles[0]->read(16000);

    ui->textEdit_source->clear();
    ui->textEdit_source->appendPlainText( QString(sourceFileData) );

    ui->textEdit_sourceHEX->clear();
    ui->textEdit_sourceHEX->appendPlainText(QString(sourceFileData.toHex()));

    ui->textEdit_result->clear();
    ui->textEdit_resultHEX->clear();

    sourceFiles[0]->seek(0);

    fileNamePath.chop(6);

    encryptedFiles[0] = new QFile(fileNamePath);

    if( !openFile(encryptedFiles[0], QIODevice::WriteOnly, "Ошибка при открытии файла для расшифровки") )
    {
        sourceFiles[0]->close();
        delete sourceFiles[0];
        delete encryptedFiles[0];
        enable_elements_after_crypt();
        return;
    }

    encryptedFiles[0]->resize(0);

    if(ui->radioButton_change->isChecked())
    {

        worker[0].start();

        int threadCount = ui->spinBox_threadCount->value();

        if( ( sourceFiles[0]->size() < 65535 ) || ( threadCount <= 1 ) )
        {

            encryptedFiles[0]->seek(0);

            worker[0].setEncrypt( encryptedFiles[0], sourceFiles[0], sourceFiles[0]->size(), true, &(g[0]), threadWorker::DECRYPT_SIMPLE );

            worker[0].start();

        }
        // ----------------------------------------
        else
        {

            qint64 fullSize = sourceFiles[0]->size();

            quint64 partSize = ( ( fullSize / BLOCK_SIZE ) / threadCount ) * BLOCK_SIZE; // 12345 / 16 / 4 = 192 * 16 = 3072

            encryptedFiles[0]->seek(0);

            worker[0].setEncrypt( encryptedFiles[0], sourceFiles[0], partSize, true, &(g[0]), threadWorker::DECRYPT_SIMPLE );

            for( int i = 1 ; ( i < threadCount ) && ( i < MAX_THREAD_COUNT ); i++ )
            {

                sourceFiles[i]    = new QFile(fileNamePath + ".crypt");
                encryptedFiles[i] = new QFile(fileNamePath);

                if( !openFile(sourceFiles[i], QIODevice::ReadOnly, "Ошибка при повторном открытии исходного файла! Повторное открытие файла нужно для многопоточного шифрования.") )
                {
                    return;
                }

                if( !openFile(encryptedFiles[i], QIODevice::ReadWrite|QIODevice::Truncate, "Ошибка при открытии одного из временных выходных файлов!") )
                {
                    return;
                }

                volatile uint32_t chunkSize = ( i < (threadCount - 1) ) ? partSize : fullSize - ( ( partSize * i ));

                sourceFiles[i]->seek( partSize * i );

                encryptedFiles[i]->seek( ( partSize * i ) - 4 );

                worker[i].setEncrypt( encryptedFiles[i],
                                      sourceFiles[i],
                                      chunkSize,
                                      false,
                                      &(g[i]),
                                      threadWorker::DECRYPT_SIMPLE );

            }

            workerCompteteCounter = 0;

            for( int i = 0 ; i < threadCount; i++ )
            {
                worker[i].start();
            }

        }
        // ---------------------------

    }
    else if(ui->radioButton_gamma->isChecked())
    {

        worker[0].setEncrypt( encryptedFiles[0], sourceFiles[0], sourceFiles[0]->size(), true, &(g[0]), threadWorker::DECRYPT_GAMMA );

        worker[0].start();

    }

    ui->pushButton_pause->setEnabled(true);
    ui->pushButton_cancel->setEnabled(true);

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

           for(int i = 0 ; i < MAX_THREAD_COUNT; i++)
           {
               g[i].clearSync();
           }

       }
       ui->lineEdit_key->clear();
       ui->lineEdit_key->setStyleSheet("QLineEdit { background: rgb(255, 255, 255); selection-background-color: rgb(0, 0, 255); }");
       ui->pushButton_setKey->setText("Задать");
       ui->progressBar_status->setValue( 0 );
       ui->pushButton_generationKey->setEnabled(true);
       for(int i = 0 ; i < MAX_THREAD_COUNT; i++)
       {
           g[i].clearKey();
       }
   }
   else
   {
       if(ui->radioButton_gamma->isChecked())
       {
           ui->lineEdit_sync->setStyleSheet("QLineEdit { background: rgb(0, 255, 255); selection-background-color: rgb(0, 0, 255); }");

           if(ui->checkBox_hex->isChecked())
           {

           }
           for(int i = 0 ; i < MAX_THREAD_COUNT; i++)
           {
               g[i].setSync(ui->lineEdit_sync->text().toStdString().c_str());
           }
       }

       ui->lineEdit_key->setStyleSheet("QLineEdit { background: rgb(0, 255, 255); selection-background-color: rgb(0, 0, 255); }");
       ui->pushButton_setKey->setText("Сбросить");

       if(ui->checkBox_hex->isChecked())
       {

       }
       for(int i = 0 ; i < MAX_THREAD_COUNT; i++)
       {
           g[i].setKey( ui->lineEdit_key->text().toStdString().c_str() );
       }
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

    int threadCount = ui->spinBox_threadCount->value();

    if( threadCount > 1 )
    {
        workerCompteteCounter++;
        if( workerCompteteCounter < ui->spinBox_threadCount->value() )
        {
            return;
        }
        else
        {

            // Сборка файлов обратно в один и закрытие исходных
            for( int i = 0 ; i < threadCount; i++ )
            {

                sourceFiles[i]->close();
                encryptedFiles[i]->close();

                delete encryptedFiles[i];
                delete sourceFiles[i];

                sourceFiles[i] = 0;
                encryptedFiles[i] = 0;

            }
        }
    }
    else
    {

        sourceFiles[0]->close();
        encryptedFiles[0]->close();

        delete encryptedFiles[0];
        delete sourceFiles[0];

        sourceFiles[0]    = 0;
        encryptedFiles[0] = 0;

    }

    ui->progressBar_status->setEnabled(false);
    ui->pushButton_pause->setEnabled(false);
    ui->pushButton_cancel->setEnabled(false);

    enable_elements_after_crypt();

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

    if( !openFile(&file, QIODevice::ReadOnly, "Не удалось открыть файл для показа содержимого во вкладке результат") )
    {
        return;
    }

    QByteArray sourceFileData = file.read(16000);

    file.close();

    ui->textEdit_result->setText( QString::fromUtf8(sourceFileData) );
    ui->textEdit_resultHEX->setText(QString(sourceFileData.toHex()));

}


void MainWindow::on_pushButton_pause_clicked()
{

    if( ui->pushButton_pause->text() == "Пауза" )
    {
        for(int i = 0 ; i < MAX_THREAD_COUNT; i++)
        {
            worker[i].pause();
        }
        ui->pushButton_pause->setText("Продолжить");
    }
    else
    {
        for(int i = 0 ; i < MAX_THREAD_COUNT; i++)
        {
            worker[i].resume();
        }
        ui->pushButton_pause->setText("Пауза");
    }

}

void MainWindow::on_pushButton_cancel_clicked()
{

    // worker.quit();
    // worker.blockSignals(true);

    int threadCount = ui->spinBox_threadCount->value();

    for(int i = 0 ; i < threadCount; i++)
    {

        worker[i].terminate();
        worker[i].wait();

        if( sourceFiles[i] != 0 )
        {

            sourceFiles[i]->close();

            encryptedFiles[i]->close();

            encryptedFiles[i]->remove();

            delete encryptedFiles[i];
            delete sourceFiles[i];

            encryptedFiles[i] = 0;
            sourceFiles[i] = 0;

        }

    }

    ui->progressBar_status->setEnabled(false);
    ui->pushButton_pause->setEnabled(false);
    ui->pushButton_cancel->setEnabled(false);

    enable_elements_after_crypt();

}

void MainWindow::on_radioButton_change_clicked()
{
    if(ui->radioButton_change->isChecked())
    {
       ui->checkBox_libgost15->setEnabled(true);
       ui->lineEdit_sync->setStyleSheet("QLineEdit { background: rgb(255, 255, 255); selection-background-color: rgb(0, 0, 255); }");
       ui->lineEdit_sync->clear();
       ui->lineEdit_sync->setEnabled(false);
       ui->label_sync->setEnabled(false);
       ui->spinBox_threadCount->setEnabled(true);
       ui->spinBox_threadCount->setValue(4);
       for(int i = 0 ; i < MAX_THREAD_COUNT; i++)
       {
           g[i].clearSync();
       }
    }
}

void MainWindow::on_radioButton_gamma_clicked()
{
    if(ui->radioButton_gamma->isChecked())
    {
        ui->checkBox_libgost15->setEnabled(false);
        ui->lineEdit_sync->setEnabled(true);
        ui->label_sync->setEnabled(true);
        ui->spinBox_threadCount->setEnabled(false);
    }
}


void MainWindow::on_checkBox_hide_clicked(bool checked)
{
    if(checked)
    {
        ui->lineEdit_key->setEchoMode(QLineEdit::Password);
    }
    else
    {
        ui->lineEdit_key->setEchoMode(QLineEdit::Normal);
    }
}


void MainWindow::on_checkBox_hex_clicked(bool checked)
{
    if(checked)
    {
        if(ui->radioButton_gamma->isChecked())
        {
            ui->lineEdit_sync->clear();
        }
        ui->lineEdit_key->clear();
    }
    else
    {
        if(ui->radioButton_gamma->isChecked())
        {
            ui->lineEdit_sync->clear();
        }
        ui->lineEdit_key->clear();
    }
}

void MainWindow::enable_elements_after_crypt()
{

    ui->pushButton_chooseFile->setEnabled(true);
    ui->lineEdit_inputFile->setEnabled(true);
    ui->lineEdit_key->setEnabled(true);
    ui->checkBox_hex->setEnabled(true);
    ui->checkBox_hide->setEnabled(true);
    ui->spinBox_keyLength->setEnabled(true);
    ui->pushButton_generationKey->setEnabled(true);
    ui->pushButton_setKey->setEnabled(true);
    ui->pushButton_decrypt->setEnabled(true);
    ui->pushButton_encrypt->setEnabled(true);
    ui->spinBox_threadCount->setEnabled(true);
    ui->radioButton_change->setEnabled(true);
    ui->radioButton_gamma->setEnabled(true);

    if( ui->radioButton_gamma->isChecked() )
    {
        ui->lineEdit_sync->setEnabled(true);
    }

}

void MainWindow::disable_elements_before_crypt()
{


    ui->pushButton_chooseFile->setEnabled(false);
    ui->lineEdit_inputFile->setEnabled(false);
    ui->lineEdit_key->setEnabled(false);
    ui->checkBox_hex->setEnabled(false);
    ui->checkBox_hide->setEnabled(false);
    ui->spinBox_keyLength->setEnabled(false);
    ui->pushButton_generationKey->setEnabled(false);
    ui->pushButton_setKey->setEnabled(false);
    ui->pushButton_decrypt->setEnabled(false);
    ui->pushButton_encrypt->setEnabled(false);
    ui->spinBox_threadCount->setEnabled(false);
    ui->lineEdit_sync->setEnabled(false);
    ui->radioButton_change->setEnabled(false);
    ui->radioButton_gamma->setEnabled(false);

}

bool MainWindow::openFile(QFile* file, QFile::OpenMode flags ,  QString errorMessage )
{

    if( file == 0 )
    {
        QMessageBox msgBox;
        msgBox.setWindowTitle("Decryptor");
        msgBox.setText("Не удалось выделить память под файл!");
        msgBox.exec();
        return false;
    }

    if(! file->open(flags) )
    {
        QMessageBox msgBox;
        msgBox.setWindowTitle("Decryptor");
        msgBox.setText(errorMessage);
        msgBox.exec();
        return false;
    }
    else
    {
        return true;
    }

}


void MainWindow::on_checkBox_libgost15_stateChanged(int arg1)
{
    if( arg1 )
    {
        for(int i = 0 ; i < MAX_THREAD_COUNT;i++)
        {
            g[i].setLibgost15(true);
        }
    }
    else
    {
        for(int i = 0 ; i < MAX_THREAD_COUNT;i++)
        {
            g[i].setLibgost15(false);
        }
    }
}

