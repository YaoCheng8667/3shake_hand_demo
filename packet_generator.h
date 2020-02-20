#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <cstdio>
#include <linux/filter.h>
#include <cstring>

struct iphead{            //IP首部
    unsigned char ip_hl:4, ip_version:4;
    unsigned char ip_tos;
    uint16_t ip_len;
    uint16_t ip_id;
    uint16_t ip_off;
    uint8_t ip_ttl;
    uint8_t ip_pro;
    uint16_t ip_sum;
    uint32_t ip_src;
    uint32_t ip_dst;
};

struct tcphead{      //TCP首部
    uint16_t tcp_sport;
    uint16_t tcp_dport;
    uint32_t tcp_seq;
    uint32_t tcp_ack;
    unsigned char tcp_off:4, tcp_len:4;
    uint8_t tcp_flag;
    uint16_t tcp_win;
    uint16_t tcp_sum;
    uint16_t tcp_urp;
    // add mss option when shake hand
    uint16_t mss_option;
    uint16_t mss;
};

struct psdhead{ //TCP伪首�?
    unsigned int saddr; //源地址
    unsigned int daddr; //目的地址
    unsigned char mbz;//置空
    unsigned char ptcl; //协议类型
    unsigned short tcpl; //TCP长度
};


struct TcpHeaderInfo {
    in_addr_t src_ip;
    in_addr_t dest_ip;
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq;
    uint32_t ack;
    int type; //type 0: shake_hand , type 1: shake_hand_ack , type 2: data.
};

unsigned short cksum(unsigned char* packet, int len){   //У�麯��
    unsigned long sum = 0;
    unsigned short * temp;
    unsigned short answer;
    temp = (unsigned short *)packet;
    unsigned short * endptr = (unsigned short*) (packet+len);
    for( ; temp < endptr; temp += 1)
        sum += *temp;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return answer;
}


typedef struct iphead iphead;
typedef struct tcphead tcphead;
typedef struct TcpHeaderInfo headerinfo;


int generate_tcp_packet(unsigned char* buf, size_t & len,headerinfo info){
    
    len = sizeof(iphead) + sizeof(tcphead);
    //if(info.type != 2) 
        len -= 4; // no mss option
    iphead* ip = (iphead*) buf;
    tcphead* tcp = (tcphead*) (buf+sizeof(iphead));
    memset(buf,0,len);

    //set the ipheader
    ip->ip_hl = 5;
    ip->ip_version = 4;
    ip->ip_tos = 0;
    ip->ip_len = htons(sizeof(struct iphead) + sizeof(struct tcphead));
    ip->ip_id = htons(13542); // random()
    ip->ip_off = htons(0x4000);
    ip->ip_ttl = 64;
    ip->ip_pro = IPPROTO_TCP;
    ip->ip_src = info.src_ip;
    ip->ip_dst = info.dest_ip;
    ip->ip_sum = cksum(buf, 20);  //计算IP首部的校验和，必须在其他字段都赋值后再赋值该字段，赋值前�?

    // set the tcp header
    int my_seq = 0; //TCP序号
    tcp->tcp_sport = info.src_port;
    tcp->tcp_dport = info.dest_port;
    tcp->tcp_seq = htonl(info.seq);
    tcp->tcp_ack = htonl(info.ack);
    if(info.type != 2){
        if(info.type == 0) tcp->tcp_flag = 0x02;  //SYN置位
        else tcp->tcp_flag = 0x12; //SYN和ACK置位
        tcp->tcp_len = 5;  //发送SYN报文段时，设置TCP首部长度�?4字节
        tcp->mss_option = 0x0204;
        tcp->mss = 1460;
    }else{
        tcp->tcp_len = 5;
    }
    tcp->tcp_off = 0;
    tcp->tcp_win = htons(29200);
    tcp->tcp_urp = htons(0);


    /*设置tcp伪首部，用于计算TCP报文段校验和*/
    struct psdhead psd;
    psd.saddr = info.src_ip; //源IP地址
    psd.daddr = info.dest_ip; //目的IP地址
    psd.mbz = 0;
    psd.ptcl = 6;  
    psd.tcpl = htons(tcp->tcp_len * 4);
    
    unsigned char buffer[100]; //用于存储TCP伪首部和TCP报文，计算校验码
    memcpy(buffer, &psd, sizeof(psd));
    memcpy(buffer+sizeof(psd), tcp, tcp->tcp_len * 4);
    tcp->tcp_sum = cksum(buffer, sizeof(psd) + tcp->tcp_len * 4);

    return 0;
}
