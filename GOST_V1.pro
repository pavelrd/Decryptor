QT       += core gui

QMAKE_CXXFLAGS_RELEASE -= -O1
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE -= -O3
QMAKE_CXXFLAGS_RELEASE += -Ofast

QMAKE_CFLAGS_RELEASE -= -O1
QMAKE_CFLAGS_RELEASE -= -O2
QMAKE_CFLAGS_RELEASE -= -O3
QMAKE_CFLAGS_RELEASE += -Ofast

QMAKE_CFLAGS_RELEASE += -Werror=return-type
QMAKE_CFLAGS_RELEASE += -Werror=float-equal
QMAKE_CFLAGS_RELEASE += -Werror=uninitialized
QMAKE_CFLAGS_RELEASE += -Werror=switch

QMAKE_CXXFLAGS_RELEASE += -Werror=return-type
QMAKE_CXXFLAGS_RELEASE += -Werror=float-equal
QMAKE_CXXFLAGS_RELEASE += -Werror=uninitialized
QMAKE_CXXFLAGS_RELEASE += -Werror=switch

QMAKE_LFLAGS_RELEASE += -static -static-libgcc -static-libstdc++

INCLUDEPATH += libgost15

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++17

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    gost12_15.cpp \
    libgost15/src/data.c \
    libgost15/src/sse2.c \
    main.cpp \
    mainwindow.cpp \
    threadworker.cpp

HEADERS += \
    gost12_15.h \
    libgost15/libgost15/internals/alignas.h \
    libgost15/libgost15/internals/compiler.h \
    libgost15/libgost15/internals/data.h \
    libgost15/libgost15/internals/inline.h \
    libgost15/libgost15/internals/language.h \
    libgost15/libgost15/internals/may_alias.h \
    libgost15/libgost15/internals/restrict.h \
    libgost15/libgost15/internals/unmangled.h \
    libgost15/libgost15/libgost15.h \
    mainwindow.h \
    threadworker.h

FORMS += \
    mainwindow.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
