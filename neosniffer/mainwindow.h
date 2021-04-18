#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#define WPCAP
#define HAVE_REMOTE

#include <QMainWindow>
#include <datastruct.h>
#include <capThread.h>
#include <QVector>
#include <memory>

#ifndef WIN32
    #include <sys/socket.h>
    #include <netinet/in.h>
#else
    #include <ws2tcpip.h>
    #include <winsock2.h>
#endif

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    int selectNaIndex;
    QString selectfilter = "all";
    pcap_if_t *alldevs;
    pcap_if_t *d;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *adhandle;
    u_int netmask;
    struct bpf_program fcode;
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    int pktCount[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    QVector<pktData> pktRaw;
    QVector<QStringList> pktVector;

    bool stopCapture;

    CapThread *capThread = nullptr;

    QVector<devInfo> getDevList();
    void firstinit();
    void interfaceAfterStart();
    void interfaceAfterStop();
    void showPktDetails();
    void showPktBin();

private:
    Ui::MainWindow *ui;

signals:
    void start();
    void stop();

public slots:
    QString reciveFilterRule(QString rule);
    void Start();
    void Stop();
    void addToView(QStringList data, int rowIndex, const u_char *pkt_data, QStringList pktcount, QStringList datainfo);

};
#endif // MAINWINDOW_H
