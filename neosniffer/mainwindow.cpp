#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QStackedWidget>
#include <QMessageBox>
#include <QDebug>
#include <QListView>
#include <QHeaderView>
#include "filterdialog.h"
#include "about.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    stopCapture = false;

    QString filterRules[] = {"all", "ipv4", "ipv6", "arp", "tcp", "udp", "icmp", "http", "more"};
    connect(ui->naBox, QOverload<int>::of(&QComboBox::activated), [=](int index) {
        this->selectNaIndex = index;
    });

    connect(ui->filterBox, QOverload<int>::of(&QComboBox::activated), [=](int index) {
        //用户自定义过滤规则
        if(index == 8) {
            FilterDialog *fd = new FilterDialog(this);
            fd->show();
            connect(fd, &FilterDialog::sendFilterRule, [=](QString rule) {
                this->selectfilter = rule;
            });
        } else {
            this->selectfilter = filterRules[index];
        }
    });

    connect(ui->startButton, &QPushButton::clicked, [=]() {
        //interfaceAfterStart();
        Start();
        capThread = new CapThread(this, alldevs, selectNaIndex, selectfilter);
        capThread->start();

        connect(capThread, &CapThread::sendDataToMain, this, &MainWindow::addToView, Qt::QueuedConnection);
    });

    connect(ui->stopButton, &QPushButton::clicked, [=]() {
        if( capThread->isRunning() ) {
            capThread->exit(0);
            //capThread->wait();
            delete capThread;
            capThread = nullptr;
        }
        Stop();

        disconnect(capThread);

    });

    connect(ui->allPktView, &QTableWidget::clicked, [=]() {

        showPktDetails();

        showPktBin();
    });

    connect(ui->aboutButton, &QPushButton::clicked, [=]() {
        About *about = new About(this);
        about->show();
    });
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::firstinit() {
    ui->startButton->setEnabled(true);
    ui->stopButton->setEnabled(false);
    ui->exitButton->setEnabled(true);

    //添加网卡列表并默认选择第一个
    ui->naBox->setEditable(false);
    QVector<devInfo> devlist = getDevList();
    if(devlist.size() <= 0) {
        ui->naBox->addItem("not found network adapter");
        ui->naBox->setCurrentIndex(0);
    }
    ui->naBox->setView(new QListView);
    for(auto devinfo : devlist) {
        ui->naBox->addItem(devinfo.name+"|"+devinfo.description);
    }

    ui->naBox->setCurrentIndex(0);
    selectNaIndex = 0;

    //添加过滤规则并默认选择第一个
    ui->filterBox->setEditable(false);
    ui->filterBox->setView(new QListView);
    QString filterRules[] = {"all", "ipv4", "ipv6", "arp", "tcp", "udp", "icmp", "http", "more"};
    for(auto filterrule : filterRules){
        ui->filterBox->addItem(filterrule);
    }
    ui->filterBox->setCurrentIndex(0);
    selectfilter = "all";

    ui->allPktView->clear();
    ui->pktDetails->clear();
    ui->binBrowser->clear();
    ui->ip4lineEdit->setText("0");
    ui->ip6lineEdit->setText("0");
    ui->arplineEdit->setText("0");
    ui->tcplineEdit->setText("0");
    ui->udplineEdit->setText("0");
    ui->icmplineEdit->setText("0");
    ui->httplineEdit->setText("0");
    ui->otherlineEdit->setText("0");

    QStringList colName;
    colName<<"Time"<<"Length"<<"Protocol"<<"SourceIPAddr"<<"DestIPAddr"<<"SourcePort"<<"DestPort";
    ui->allPktView->horizontalHeader()->setVisible(true);
    ui->allPktView->setColumnCount(7);
    ui->allPktView->setHorizontalHeaderLabels(colName);
    QFont headerFont;
    headerFont.setBold(true);
    ui->allPktView->horizontalHeader()->setFont(headerFont);
    //ui->binBrowser->append("second done\n");

    // 设置整行选中
    ui->allPktView->setSelectionBehavior ( QAbstractItemView::SelectRows);
    ui->allPktView->setSelectionMode(QAbstractItemView::SingleSelection);

    // 设置不可编辑
    ui->allPktView->setEditTriggers(QAbstractItemView::NoEditTriggers);

    //Header 自动填充表
    ui->allPktView->horizontalHeader()->setStretchLastSection(true);
    //ui->binBrowser->append("3333333 done\n");
    //自动调整列宽
    for(int i = 0; i <= 6; i++) {
        ui->allPktView->horizontalHeader()->setSectionResizeMode(i, QHeaderView::ResizeToContents);
    }
}

QVector<devInfo> MainWindow::getDevList() {
    QVector<devInfo> devlist;

    if(pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        return devlist;
    }
    for(d = alldevs; d; d = d->next){
        devInfo devinfo;
        devinfo.name = d->name;
        devinfo.description = "not found description";
        if(d->description) {
            devinfo.description = d->description;
        }
        devlist.push_back(devinfo);
    }
    return devlist;
}

QString MainWindow::reciveFilterRule(QString rule){
    return rule;
}

void MainWindow::interfaceAfterStart() {
    ui->naBox->setEnabled(false);
    ui->filterBox->setEnabled(false);
    ui->startButton->setEnabled(false);
    ui->stopButton->setEnabled(true);

    ui->allPktView->setRowCount(0);
//    ui->allPktView->reset();
//    QStringList colName;
//    colName<<"Time"<<"Length"<<"Protocol"<<"SourceIPAddr"<<"DestIPAddr"<<"SourcePort"<<"DestPort";
//    ui->allPktView->horizontalHeader()->setVisible(true);
//    ui->allPktView->setColumnCount(7);
//    ui->allPktView->setHorizontalHeaderLabels(colName);
//    QFont headerFont;
//    headerFont.setBold(true);
//    ui->allPktView->horizontalHeader()->setFont(headerFont);

    ui->pktDetails->clear();
    ui->binBrowser->clear();
    ui->ip4lineEdit->setText("0");
    ui->ip6lineEdit->setText("0");
    ui->arplineEdit->setText("0");
    ui->tcplineEdit->setText("0");
    ui->udplineEdit->setText("0");
    ui->icmplineEdit->setText("0");
    ui->httplineEdit->setText("0");
    ui->otherlineEdit->setText("0");

    //memset(pktCount, 0, sizeof(pktCount));
    pktRaw.clear();
    pktVector.clear();
}

void MainWindow::interfaceAfterStop() {
    ui->naBox->setEnabled(true);
    ui->filterBox->setEnabled(true);
    ui->startButton->setEnabled(true);
    ui->stopButton->setEnabled(false);
}

void MainWindow::Start() {
    //ui->binBrowser->append("now click init\n");
    //初始化界面
    interfaceAfterStart();
}

void MainWindow::Stop() {
    stopCapture = true;

    interfaceAfterStop();
}

void MainWindow::addToView(QStringList data, int rowIndex, const u_char *pkt_data, QStringList pktcount, QStringList datainfo) {
    pktData pktdata;
    pktdata.len = data[1].toInt();
    pktdata.pkt_data = pkt_data;
    //pktdata.pkt_data = deepcopy;
    pktRaw.push_back(pktdata);

    pktVector.push_back(datainfo);

    ui->allPktView->insertRow(rowIndex);
    for(int k = 0; k <= 6; k++) {
        //ui->binBrowser->append(data[k]);
        ui->allPktView->setItem(rowIndex, k, new QTableWidgetItem(data[k]));
    }

    //设置居中
    for(int k = 0; k <= 6;k++){
        ui->allPktView->item(rowIndex, k)->setTextAlignment(Qt::AlignHCenter|Qt::AlignVCenter);
    }

    ui->ip4lineEdit->setText(pktcount[0]);
    ui->ip6lineEdit->setText(pktcount[1]);
    ui->arplineEdit->setText(pktcount[2]);
    ui->tcplineEdit->setText(pktcount[3]);
    ui->udplineEdit->setText(pktcount[4]);
    ui->icmplineEdit->setText(pktcount[5]);
    ui->httplineEdit->setText(pktcount[6]);
    ui->otherlineEdit->setText(pktcount[7]);

}

void MainWindow::showPktDetails() {
    auto index = ui->allPktView->currentRow();
    //qDebug()<<index;
    if(index >= pktVector.size()){
        QTreeWidgetItem *other = new QTreeWidgetItem(ui->pktDetails, QStringList("Other"));
        other->setExpanded(true);
        return;
    }
    QStringList datainfo = pktVector[index];
    int datalen = datainfo.size();
    //qDebug()<<datainfo;

    ui->pktDetails->clear();

    QTreeWidgetItem *ethernet = new QTreeWidgetItem(ui->pktDetails, QStringList("Ethernet II"));
    ethernet->setExpanded(true);
    for(int i = 0;i<3 && i < datalen;i++){
        ethernet->addChild(new QTreeWidgetItem(ethernet, QStringList(datainfo[i])));
    }

    if(2 < datalen && datainfo[2] == "IPv4") {
        QTreeWidgetItem *ipv4 = new QTreeWidgetItem(ui->pktDetails, QStringList("Internet Protocol Version 4"));
        ipv4->setExpanded(true);
        for(int i = 3; i < 3+13 && i < datalen; i++) {
            ipv4->addChild(new QTreeWidgetItem(ipv4, QStringList(datainfo[i])));
        }

        if(11 < datalen && datainfo[11] == "TCP") {
            QTreeWidgetItem *tcp = new QTreeWidgetItem(ui->pktDetails, QStringList("Transmission Control Protocol"));
            tcp->setExpanded(true);
            for(int i = 3+13;i < 3+13+15 && i < datalen;i++){
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(datainfo[i])));
            }

        } else if(11 < datalen && datainfo[11] == "UDP") {
            QTreeWidgetItem *udp = new QTreeWidgetItem(ui->pktDetails, QStringList("User Datagram Protocol"));
            udp->setExpanded(true);
            for(int i = 3+13;i < 3+13+5 && i < datalen;i++){
                udp->addChild(new QTreeWidgetItem(udp, QStringList(datainfo[i])));
            }

        } else if(11 < datalen && datainfo[11] == "ICMP") {
            QTreeWidgetItem *icmp = new QTreeWidgetItem(ui->pktDetails, QStringList("Internet Control Message Protocol"));
            icmp->setExpanded(true);
            for(int i = 3+13;i < 3+13+5 && i < datalen;i++){
                icmp->addChild(new QTreeWidgetItem(icmp, QStringList(datainfo[i])));
            }

        } else {
            QTreeWidgetItem *other = new QTreeWidgetItem(ui->pktDetails, QStringList("Other"));
            other->setExpanded(true);
        }
    } else if(2 < datalen && datainfo[2] == "IPv6") {
        QTreeWidgetItem *ipv6 = new QTreeWidgetItem(ui->pktDetails, QStringList("Internet Protocol Version 6"));
        ipv6->setExpanded(true);
        for(int i = 3; i < 3+8 && i < datalen; i++){
            ipv6->addChild(new QTreeWidgetItem(ipv6, QStringList(datainfo[i])));
        }

        if(7 < datalen && datainfo[7] == "TCP") {
            QTreeWidgetItem *tcp = new QTreeWidgetItem(ui->pktDetails, QStringList("Transmission Control Protocol"));
            tcp->setExpanded(true);
            for(int i = 3+8;i < 3+8+15 && i < datalen;i++){
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(datainfo[i])));
            }

        } else if(7 < datalen && datainfo[7] == "UDP") {
            QTreeWidgetItem *udp = new QTreeWidgetItem(ui->pktDetails, QStringList("User Datagram Protocol"));
            udp->setExpanded(true);
            for(int i = 3+8;i < 3+8+5 && i < datalen;i++){
                udp->addChild(new QTreeWidgetItem(udp, QStringList(datainfo[i])));
            }

        } else if(7 < datalen && datainfo[7] == "ICMP") {
            QTreeWidgetItem *icmp = new QTreeWidgetItem(ui->pktDetails, QStringList("Internet Control Message Protocol"));
            icmp->setExpanded(true);
            for(int i = 3+8;i < 3+8+5 && i < datalen;i++){
                icmp->addChild(new QTreeWidgetItem(icmp, QStringList(datainfo[i])));
            }

        } else {
            QTreeWidgetItem *other = new QTreeWidgetItem(ui->pktDetails, QStringList("Other"));
            other->setExpanded(true);
        }

    } else if(2 < datalen && datainfo[2] == "ARP") {
        QTreeWidgetItem *arp = new QTreeWidgetItem(ui->pktDetails, QStringList("Address Resolution Protocol"));
        arp->setExpanded(true);
        for(int i = 3; i < 3+9 && i < datalen; i++){
            arp->addChild(new QTreeWidgetItem(arp, QStringList(datainfo[i])));
        }

        if(4 < datalen && datainfo[4] == "TCP") {
            QTreeWidgetItem *tcp = new QTreeWidgetItem(ui->pktDetails, QStringList("Transmission Control Protocol"));
            tcp->setExpanded(true);
            for(int i = 3+9;i < 3+9+15 && i < datalen;i++){
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(datainfo[i])));
            }

        } else if(4 < datalen && datainfo[4] == "UDP") {
            QTreeWidgetItem *udp = new QTreeWidgetItem(ui->pktDetails, QStringList("User Datagram Protocol"));
            udp->setExpanded(true);
            for(int i = 3+9;i < 3+9+5 && i < datalen;i++){
                udp->addChild(new QTreeWidgetItem(udp, QStringList(datainfo[i])));
            }

        } else if(4 < datalen && datainfo[4] == "ICMP") {
            QTreeWidgetItem *icmp = new QTreeWidgetItem(ui->pktDetails, QStringList("Internet Control Message Protocol"));
            icmp->setExpanded(true);
            for(int i = 3+9;i < 3+9+5 && i < datalen;i++){
                icmp->addChild(new QTreeWidgetItem(icmp, QStringList(datainfo[i])));
            }

        } else {
            QTreeWidgetItem *other = new QTreeWidgetItem(ui->pktDetails, QStringList("Other"));
            other->setExpanded(true);
        }

    } else {
        QTreeWidgetItem *other = new QTreeWidgetItem(ui->pktDetails, QStringList("Other"));
        other->setExpanded(true);

    }
}

void MainWindow::showPktBin() {
    auto index = ui->allPktView->currentRow();

    ui->binBrowser->clear();
    u_int len = pktRaw[index].len;

    QString more = " ";
    if(len > 350) {
        len = 350;
        more = more + "···(.etc)";
    }
    pktData pp = pktRaw[index];
    const u_char *pdd = pp.pkt_data;

    for(u_int i = 0; pdd!=nullptr && i < len; i++, pdd = pdd + 1) {
        QString bin = QString("%1").arg((*pdd), 2, 16, QLatin1Char('0'));

        ui->binBrowser->insertPlainText(bin);
    }

    ui->binBrowser->insertPlainText(more);
}
