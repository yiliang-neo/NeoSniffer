QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++11

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    about.cpp \
    capThread.cpp \
    filterdialog.cpp \
    main.cpp \
    mainwindow.cpp

HEADERS += \
    ../WpdPack/Include/Packet32.h \
    ../WpdPack/Include/Win32-Extensions.h \
    ../WpdPack/Include/bittypes.h \
    ../WpdPack/Include/ip6_misc.h \
    ../WpdPack/Include/pcap-bpf.h \
    ../WpdPack/Include/pcap-namedb.h \
    ../WpdPack/Include/pcap-stdinc.h \
    ../WpdPack/Include/pcap.h \
    ../WpdPack/Include/pcap/bluetooth.h \
    ../WpdPack/Include/pcap/bpf.h \
    ../WpdPack/Include/pcap/namedb.h \
    ../WpdPack/Include/pcap/pcap.h \
    ../WpdPack/Include/pcap/sll.h \
    ../WpdPack/Include/pcap/usb.h \
    ../WpdPack/Include/pcap/vlan.h \
    ../WpdPack/Include/remote-ext.h \
    about.h \
    capThread.h \
    datastruct.h \
    filterdialog.h \
    mainwindow.h

FORMS += \
    about.ui \
    filterdialog.ui \
    mainwindow.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

DISTFILES += \
    ../WpdPack/Lib/Packet.lib \
    ../WpdPack/Lib/libpacket.a \
    ../WpdPack/Lib/libwpcap.a \
    ../WpdPack/Lib/wpcap.lib \
    ../WpdPack/Lib/x64/Packet.lib \
    ../WpdPack/Lib/x64/wpcap.lib

INCLUDEPATH += ../WpdPack/Include
LIBS += -L ../WpdPack/Lib/x64/ -lwpcap -lws2_32

LIBS += -liphlpapi

RESOURCES += \
    aboutimg.qrc
