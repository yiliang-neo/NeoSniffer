#ifndef DATASTRUCT_H
#define DATASTRUCT_H

#include <QString>
#include <QVector>
#include <pcap.h>

struct devInfo {
    QString name = "";
    QString description = "";
};

struct ethHeader { //3
    u_char src_addr[6];
    u_char dest_addr[6];
    u_short type;
};

struct  ipHeader{ //13
    u_char ver_ihl;
    u_char tos;
    u_short tlen;
    u_short identification;
    u_short flag_fo;
    u_char ttl;
    u_char proto; //11
    u_short crc;
    u_char src_addr[4];
    u_char dest_addr[4];
    u_int op_pad;
};

struct ipv6Header { //8
    u_int version:4,				//版本
        flowtype:8,			//流类型
        flowid:20;				//流标签
    u_short plen;					//有效载荷长度
    u_char nh;	//7					//下一个头部
    u_char hlim;					//跳限制
    u_short src_addr[8];			//源地址
    u_short dest_addr[8];
};

struct arpHeader { //9
    u_short ar_hw;						//硬件类型
    u_short ar_port;//4					//协议类型
    u_char ar_hln;						//硬件地址长度
    u_char ar_pln;						//协议地址长度
    u_short ar_op;						//操作码，1为请求 2为回复
    u_char ar_srcmac[6];			//发送方MAC
    u_char ar_srcip[4];				//发送方IP
    u_char ar_destmac[6];			//接收方MAC
    u_char ar_destip[4];
};

struct tcpHeader { //15
    u_short src_port;
    u_short dest_port;
    u_int seq;
    u_int ack;
    u_short hl_flag;
    u_short windowsize;
    u_short checksum;
    u_short urgpoint;
    u_int ops;
};

struct udpHeader { //5
    u_short src_port;
    u_short dest_port;
    u_short udplen;
    u_short checksum;
    u_int data;
};

struct icmpHeader { //5
    u_char type;
    u_char code;
    u_short checksum;
    u_short id;
    u_short seq;
};

struct pktData {
    int len;
    //QVector<u_char> pkt_data;
    const u_char *pkt_data;
};

//struct httpHeader {

//};

#endif // DATASTRUCT_H
