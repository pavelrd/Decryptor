#ifndef THREADWORKER_H
#define THREADWORKER_H

#include <QObject>
#include <QDebug>
#include <QThread>
#include <QFile>
#include "gost12_15.h"

#include <QMutex>
#include <QWaitCondition>

class threadWorker : public QThread
{
    Q_OBJECT
public:
    void run();
    ~threadWorker()
    {
    }
    void setEncrypt(QFile* _encryptedFile, QFile* _sourceFile, gost12_15 *_gost12_15_Worker , bool _isEncrypt);
    void resume();
    void pause();
private:
    QFile* encryptedFile = 0;
    QFile* sourceFile = 0;
    gost12_15 *gost12_15_Worker = 0;
    bool isEncrypt = true;

    QMutex sync;
    QWaitCondition pauseCond;
    bool pauseFlag = false;

signals:
    void progressChanged(int value);
    void cryptCompteted(bool);
};

#endif // THREADWORKER_H