#include "capThread.h"
#include <QMessageBox>
#include <QDebug>

CapThread::CapThread(QMainWindow *w, pcap_if_t *alldevs, int selectNaIndex, QString selectfilter) {
    this->alldevs = alldevs;
    this->w = w;
    this->selectNaIndex = selectNaIndex;
    this->selectfilter = selectfilter;
    memset(pktCount, 0, sizeof(pktCount));
}

CapThread::~CapThread(){
    pcap_close(adhandle);

    requestInterruption();
    quit();
    wait();
}

void CapThread::run() {
    stopCapture = false;

    //打开指定网卡，设置过滤条件，并抓包
    d = alldevs;
    for(int i = 0; i < selectNaIndex; i++){
        d = d->next;
    }

    if((adhandle = pcap_open_live(d->name,
                             65536,
                             1,
                             1000,
                             errbuf)) == NULL) {
        //ui->binBrowser->clear();
        //ui->binBrowser->setText("Unable to open the adapter. not supported by WinPcap");
    }
    //ui->binBrowser->append("open fin\n");

    //检查是否是以太网
    if(checkEth() == false) {
        //ui->binBrowser->clear();
        //ui->binBrowser->setText("not support this network adapter");
    }
    //ui->binBrowser->append("checketh fin\n");
    //获取netmask(设置过滤条件时需要)
    netmask = getNetmask();

    //设置过滤条件
    if(setFilter(selectfilter) == false) {
        //interfaceAfterStop();
        return;
    } else {
        //pcap_freealldevs(alldevs);
        //开始抓包
        startCapture();

        //抓包后释放网卡
        //pcap_freealldevs(alldevs);
    }
    //ui->binBrowser->append("set finished\n");
}

bool CapThread::checkEth() {
    if(pcap_datalink(this->adhandle) != DLT_EN10MB){
        return false;
    }
    return true;
}

u_int CapThread::getNetmask() {
    u_int netmask;
    if(d->addresses != NULL) {
        netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    } else {
        netmask = 0xffffff;
    }
    return netmask;
}

bool CapThread::setFilter(QString rule) {
    //ui->binBrowser->setText(rule);
    if(rule == "all") return true;
    char *Rule;
    QByteArray ba = rule.toLatin1();
    Rule = ba.data();
    if(pcap_compile(adhandle, &fcode, Rule, 1, netmask) < 0 ) {
        //ui->binBrowser->clear();
        //ui->binBrowser->setText("Unable to compile the packet filter. Check the syntax.");
        return false;
    }
    //ui->binBrowser->append("\ncompile finished");
    if(pcap_setfilter(adhandle, &fcode) < 0) {
        //ui->binBrowser->clear();
        //ui->binBrowser->setText("Error setting the filter.");
        return false;
    }
    return true;
}

void CapThread::startCapture() {
    //ui->stopButton->setEnabled(true);

    int res;
    int rowIndex = 0;
    while((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
        if(res == 0) continue;

        QString data[7];
        QStringList datainfo;

        struct tm ltime;
        char timestr[16];

        ethHeader *eh = (ethHeader *)pkt_data;
        QString tmp;
        for(int i = 0; i < 6; i++) {
            tmp = tmp + QString::number(eh->src_addr[i]);
            if(i != 5)tmp = tmp + ":";
        }
        datainfo<<tmp;
        QString srcMac = tmp;
        tmp.clear();
        for(int i = 0; i < 6; i++) {
            tmp = tmp + QString::number(eh->dest_addr[i]);
            if(i != 5)tmp = tmp + ":";
        }
        datainfo<<tmp;
        QString destMac = tmp;

        ipHeader *ih;
        ipv6Header *iv6h;
        arpHeader *ah;
        tcpHeader *th;
        udpHeader *uh;
        icmpHeader *icmph;

        u_int iph_len;
        u_int ipv6_len;
        u_int arp_len;
        u_short sport, dport;

        time_t local_tv_sec;

        local_tv_sec = header->ts.tv_sec;
        localtime_s(&ltime, &local_tv_sec);
        strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);
        data[0] = timestr;
        data[1] = QString::number(header->len);

        ih = (ipHeader *)(pkt_data + 14);
        iv6h = (ipv6Header *)(pkt_data + 14);
        ah = (arpHeader *)(pkt_data + 14);

        //ipv4
        if(ntohs(eh->type) == 2048) {
            pktCount[0]++;
            datainfo<<"IPv4";
            datainfo<<"IPv4";

            // 首部长度指的是首部占32bit字的数目
            data[3] = QString::number(ih->src_addr[0]) + "." +
                    QString::number(ih->src_addr[1]) + "." +
                    QString::number(ih->src_addr[2]) + "." +
                    QString::number(ih->src_addr[3]);
            data[4] = QString::number(ih->dest_addr[0]) + "." +
                    QString::number(ih->dest_addr[1]) + "." +
                    QString::number(ih->dest_addr[2]) + "." +
                    QString::number(ih->dest_addr[3]);
            //根据ip报文首部的protocol域确定下一首部隶属于哪个协议
            iph_len = (ih->ver_ihl & 0xf) * 4;
            datainfo.append(QString::number(iph_len));
            datainfo.append(QString::number(ih->tos));
            datainfo.append(QString::number(ih->tlen));
            datainfo.append(QString::number(ih->identification));
            datainfo.append(QString::number(ih->flag_fo & 0xe000));
            datainfo.append(QString::number(ih->flag_fo & 0x1fff));
            datainfo.append(QString::number(ih->ttl));

            uh = (udpHeader *)(pkt_data + iph_len);
            th = (tcpHeader *)(pkt_data + iph_len);
            icmph = (icmpHeader *)(pkt_data + iph_len);
            if(ih->proto == 6) {
                pktCount[3]++;
                datainfo<<"TCP";
                datainfo.append(QString::number(ih->crc));
                datainfo.append(data[3]);
                datainfo.append(data[4]);
                datainfo.append(QString::number(ih->op_pad));
                data[2] = "TCP";
                sport = ntohs(th->src_port);
                dport = ntohs(th->dest_port);
                data[5] = QString::number(sport);
                data[6] = QString::number(dport);

                datainfo.append(data[5]);
                datainfo.append(data[6]);
                datainfo.append(QString::number(th->seq));
                datainfo.append(QString::number(th->ack));
                datainfo.append(QString::number(th->hl_flag & 0xf000));
                datainfo.append(QString::number(th->hl_flag & 0x0020));
                datainfo.append(QString::number(th->hl_flag & 0x0010));
                datainfo.append(QString::number(th->hl_flag & 0x0008));
                datainfo.append(QString::number(th->hl_flag & 0x0004));
                datainfo.append(QString::number(th->hl_flag & 0x0002));
                datainfo.append(QString::number(th->hl_flag & 0x0001));
                datainfo.append(QString::number(th->windowsize));
                datainfo.append(QString::number(th->checksum));
                datainfo.append(QString::number(th->urgpoint));
                datainfo.append(QString::number(th->ops));
            } else if(ih->proto == 17) {
                pktCount[4]++;
                data[2] = "UDP";
                datainfo<<"UDP";
                datainfo.append(QString::number(ih->crc));
                datainfo.append(data[3]);
                datainfo.append(data[4]);
                datainfo.append(QString::number(ih->op_pad));
                sport = ntohs(uh->src_port);
                dport = ntohs(uh->dest_port);
                data[5] = QString::number(sport);
                data[6] = QString::number(dport);

                datainfo.append(data[5]);
                datainfo.append(data[6]);
                datainfo.append(QString::number(uh->udplen));
                datainfo.append(QString::number(uh->checksum));
                datainfo.append(QString::number(uh->data));

            } else if(ih->proto == 1){
                pktCount[5]++;
                data[2] = "ICMP";
                datainfo<<"ICMP";
                datainfo.append(QString::number(ih->crc));
                datainfo.append(data[3]);
                datainfo.append(data[4]);
                datainfo.append(QString::number(ih->op_pad));
                data[5] = "other";
                data[6] = "other";
                datainfo.append(QString::number(icmph->type));
                datainfo.append(QString::number(icmph->code));
                datainfo.append(QString::number(icmph->checksum));
                datainfo.append(QString::number(icmph->id));
                datainfo.append(QString::number(icmph->seq));
            } else {
                pktCount[7]++;
                datainfo<<"Other";
                datainfo<<"ICMP";
                datainfo.append(QString::number(ih->crc));
                datainfo.append(data[3]);
                datainfo.append(data[4]);
                datainfo.append(QString::number(ih->op_pad));
                data[2] = "Other";
                data[5] = "Other";
                data[6] = "Other";
            }
        } else if(ntohs(eh->type) == 34525) { // ipv6
            pktCount[1]++;
            datainfo<<"IPv6";
            datainfo<<"IPv6";
            datainfo.append(QString::number(iv6h->flowtype));
            datainfo.append(QString::number(iv6h->flowid));
            datainfo.append(QString::number(iv6h->plen));

            QString src = "";
            for(int i = 0; i < 8; i++) {
                src = src + QString::number(iv6h->src_addr[i]);
                if(i != 7)src = src + ".";
            }
            data[3] = src;
            QString dest = "";
            for(int i = 0; i < 8; i++) {
                dest = dest + QString::number(iv6h->dest_addr[i]);
                if(i != 7)dest = dest + ".";
            }
            data[4] = dest;

            ipv6_len = iv6h->plen;
            uh = (udpHeader *)(pkt_data + ipv6_len);
            th = (tcpHeader *)(pkt_data + ipv6_len);
            icmph = (icmpHeader *)(pkt_data + ipv6_len);
            if(iv6h->nh == 6) {
                pktCount[3]++;
                data[2] = "TCP";
                datainfo<<"TCP";
                datainfo.append(QString::number(iv6h->hlim));
                datainfo.append(data[3]);
                datainfo.append(data[4]);

                sport = ntohs(th->src_port);
                dport = ntohs(th->dest_port);
                data[5] = QString::number(sport);
                data[6] = QString::number(dport);

                datainfo.append(data[5]);
                datainfo.append(data[6]);
                datainfo.append(QString::number(th->seq));
                datainfo.append(QString::number(th->ack));
                datainfo.append(QString::number(th->hl_flag & 0xf000));
                datainfo.append(QString::number(th->hl_flag & 0x0020));
                datainfo.append(QString::number(th->hl_flag & 0x0010));
                datainfo.append(QString::number(th->hl_flag & 0x0008));
                datainfo.append(QString::number(th->hl_flag & 0x0004));
                datainfo.append(QString::number(th->hl_flag & 0x0002));
                datainfo.append(QString::number(th->hl_flag & 0x0001));
                datainfo.append(QString::number(th->windowsize));
                datainfo.append(QString::number(th->checksum));
                datainfo.append(QString::number(th->urgpoint));
                datainfo.append(QString::number(th->ops));

            } else if(iv6h->nh == 17) {
                pktCount[4]++;
                data[2] = "UDP";
                datainfo<<"UDP";
                datainfo.append(QString::number(iv6h->hlim));
                datainfo.append(data[3]);
                datainfo.append(data[4]);

                sport = ntohs(uh->src_port);
                dport = ntohs(uh->dest_port);
                data[5] = QString::number(sport);
                data[6] = QString::number(dport);

                datainfo.append(data[5]);
                datainfo.append(data[6]);
                datainfo.append(QString::number(uh->udplen));
                datainfo.append(QString::number(uh->checksum));
                datainfo.append(QString::number(uh->data));

            } else if(iv6h->nh == 1){
                pktCount[5]++;
                datainfo<<"ICMP";
                datainfo.append(QString::number(iv6h->hlim));
                datainfo.append(data[3]);
                datainfo.append(data[4]);
                data[2] = "ICMP";
                data[5] = "Other";
                data[6] = "Other";

                datainfo.append(QString::number(icmph->type));
                datainfo.append(QString::number(icmph->code));
                datainfo.append(QString::number(icmph->checksum));
                datainfo.append(QString::number(icmph->id));
                datainfo.append(QString::number(icmph->seq));
            } else {
                pktCount[7]++;
                datainfo<<"Other";
                datainfo.append(QString::number(iv6h->hlim));
                datainfo.append(data[3]);
                datainfo.append(data[4]);
                data[2] = "Other";
                data[5] = "Other";
                data[6] = "Other";
            }

        } else if(ntohs(eh->type) == 2054) { // arp
            pktCount[2]++;
            datainfo<<"ARP";
            datainfo.append(QString::number(ah->ar_hw));

            data[3] = QString::number(ah->ar_srcip[0]) + "." +
                    QString::number(ah->ar_srcip[1]) + "." +
                    QString::number(ah->ar_srcip[2]) + "." +
                    QString::number(ah->ar_srcip[3]);
            data[4] = QString::number(ah->ar_destip[0]) + "." +
                    QString::number(ah->ar_destip[1]) + "." +
                    QString::number(ah->ar_destip[2]) + "." +
                    QString::number(ah->ar_destip[3]);

            arp_len = 7 * 4;
            uh = (udpHeader *)(pkt_data + arp_len);
            th = (tcpHeader *)(pkt_data + arp_len);
            icmph = (icmpHeader *)(pkt_data + arp_len);
            if(ah->ar_port == 6) {
                pktCount[3]++;
                data[2] = "TCP";
                datainfo<<"TCP";
                datainfo.append(QString::number(ah->ar_hln));
                datainfo.append(QString::number(ah->ar_pln));
                datainfo.append(QString::number(ah->ar_op));
                datainfo.append(srcMac);
                datainfo.append(data[3]);
                datainfo.append(destMac);
                datainfo.append(data[4]);

                sport = ntohs(th->src_port);
                dport = ntohs(th->dest_port);
                data[5] = QString::number(sport);
                data[6] = QString::number(dport);

                datainfo.append(data[5]);
                datainfo.append(data[6]);
                datainfo.append(QString::number(th->seq));
                datainfo.append(QString::number(th->ack));
                datainfo.append(QString::number(th->hl_flag & 0xf000));
                datainfo.append(QString::number(th->hl_flag & 0x0020));
                datainfo.append(QString::number(th->hl_flag & 0x0010));
                datainfo.append(QString::number(th->hl_flag & 0x0008));
                datainfo.append(QString::number(th->hl_flag & 0x0004));
                datainfo.append(QString::number(th->hl_flag & 0x0002));
                datainfo.append(QString::number(th->hl_flag & 0x0001));
                datainfo.append(QString::number(th->windowsize));
                datainfo.append(QString::number(th->checksum));
                datainfo.append(QString::number(th->urgpoint));
                datainfo.append(QString::number(th->ops));
            } else if(ah->ar_port == 17) {
                pktCount[4]++;
                data[2] = "UDP";
                datainfo<<"UDP";
                datainfo.append(QString::number(ah->ar_hln));
                datainfo.append(QString::number(ah->ar_pln));
                datainfo.append(QString::number(ah->ar_op));
                datainfo.append(srcMac);
                datainfo.append(data[3]);
                datainfo.append(destMac);
                datainfo.append(data[4]);

                sport = ntohs(uh->src_port);
                dport = ntohs(uh->dest_port);
                data[5] = QString::number(sport);
                data[6] = QString::number(dport);

                datainfo.append(data[5]);
                datainfo.append(data[6]);
                datainfo.append(QString::number(uh->udplen));
                datainfo.append(QString::number(uh->checksum));
                datainfo.append(QString::number(uh->data));

            } else if(ah->ar_port == 1){
                pktCount[5]++;
                data[2] = "ICMP";
                datainfo<<"ICMP";
                datainfo.append(QString::number(ah->ar_hln));
                datainfo.append(QString::number(ah->ar_pln));
                datainfo.append(QString::number(ah->ar_op));
                datainfo.append(srcMac);
                datainfo.append(data[3]);
                datainfo.append(destMac);
                datainfo.append(data[4]);

                data[5] = "Other";
                data[6] = "Other";
                datainfo.append(QString::number(icmph->type));
                datainfo.append(QString::number(icmph->code));
                datainfo.append(QString::number(icmph->checksum));
                datainfo.append(QString::number(icmph->id));
                datainfo.append(QString::number(icmph->seq));
            } else {
                pktCount[7]++;
                data[2] = "Other";
                datainfo<<"ICMP";
                datainfo.append(QString::number(ah->ar_hln));
                datainfo.append(QString::number(ah->ar_pln));
                datainfo.append(QString::number(ah->ar_op));
                datainfo.append(srcMac);
                datainfo.append(data[3]);
                datainfo.append(destMac);
                datainfo.append(data[4]);

                data[5] = "Other";
                data[6] = "Other";
            }
        } else {
            pktCount[7]++;
            datainfo<<"Other";
            for(int i = 2; i < 7; i++) {
                data[i] = "other";
            }
        }

        QStringList data_tmp;
        for(int k =0; k < 7; k++) {
            data_tmp.append(data[k]);
        }
        QStringList pktcount_tmp;
        for(int k = 0; k < 8; k++) {
            pktcount_tmp.append(QString::number(pktCount[k]));
        }

        // 手动深拷贝
        /*QVector<u_char> deepcopy;
        u_char* it = (u_char *)pkt_data;
        for(;it;it++) {
            deepcopy.push_back(*it);
        }*/
        emit sendDataToMain(data_tmp, rowIndex, pkt_data, pktcount_tmp, datainfo);
        rowIndex++;
    }
}

