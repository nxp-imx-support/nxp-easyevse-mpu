QT       += core
QT       += widgets
QT       += network

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++17

SOURCES += \
    ../common/comms.c \
    ../common/logger.c \
    ../common/utils.c \
    main.cpp \
    mainwindow.cpp

HEADERS += \
    ../include/comms.h \
    ../include/logger.h \
    ../include/typedefs.h \
    ../include/utils.h \
    mainwindow.h

FORMS += \
    mainwindow.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

RESOURCES += \
    resources.qrc

DISTFILES += \
    CMakeLists.txt
