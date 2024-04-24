#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

public slots:

    void encryptShow(bool isEncrypt);

private slots:
    void on_pushButton_chooseFile_clicked();

    void on_pushButton_encrypt_clicked();

    void on_pushButton_decrypt_clicked();

    void on_pushButton_setKey_clicked();

    void on_pushButton_generationKey_clicked();

    void on_pushButton_pause_clicked();

    void on_pushButton_cancel_clicked();

    void on_radioButton_change_clicked();

    void on_radioButton_gamma_clicked();

    void on_checkBox_hide_clicked(bool checked);

    void on_checkBox_hex_clicked(bool checked);

private:
    Ui::MainWindow *ui;
};
#endif // MAINWINDOW_H
