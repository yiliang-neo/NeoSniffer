#ifndef CAPTHREAD_H
#define CAPTHREAD_H

#include <QThread>
#include <QMainWindow>
#include <QVector>
#include "datastruct.h"

#define WPCAP
#define HAVA_REMOTE

#include "pcap.h"

#ifndef WIN32
    #include <sys/socket.h>
    #include <netinet/in.h>
#else
    #include <ws2tcpip.h>
    #include <winsock2.h>
#endif

class CapThread : public QThread {

    Q_OBJECT

public:
    //通过构造函数从main获得
    pcap_if_t *alldevs;
    QMainWindow *w;
    int selectNaIndex;
    QString selectfilter;

    //自己用的
    pcap_if_t *d;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *adhandle;
    u_int netmask;
    struct bpf_program fcode;
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    int pktCount[8];

    bool stopCapture;

    CapThread(QMainWindow *w, pcap_if_t *alldevs, int selectNaIndex, QString selectfilter);
    ~CapThread();
    void run();

    bool checkEth();
    u_int getNetmask();
    bool setFilter(QString rule);
    void startCapture();
signals:
    void sendDataToMain(QStringList data_tmp, int rowIndex, const u_char *pkt_data, QStringList pktcount, QStringList datainfo);
};

#endif // CAPTHREAD_H
