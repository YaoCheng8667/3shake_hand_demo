#include "packet_generator.h"

#define LOCAL_PORT_USED 17001
#define REMOTE_PORT_USED 17000

#define LOCAL_ADDR "202.120.38.131"
#define REMOTE_ADDR "202.120.38.100"

int recv_rawsockfd , send_rawsockfd;
sockaddr_in server_addr,clnt_addr;

char sendbuf[2000];
char recvbuf[2000];
// filter the packet to port 11222
// tcpdump -dd 'tcp[2:2] == 17001 and tcp[tcpflags] & tcp-rst == 0'
struct sock_filter bpf_code[] = {
    { 0x28, 0, 0, 0x0000000c },
    { 0x15, 0, 10, 0x00000800 },
    { 0x30, 0, 0, 0x00000017 },
    { 0x15, 0, 8, 0x00000006 },
    { 0x28, 0, 0, 0x00000014 },
    { 0x45, 6, 0, 0x00001fff },
    { 0xb1, 0, 0, 0x0000000e },
    { 0x48, 0, 0, 0x00000010 },
    { 0x15, 0, 3, 0x00004269 },
    { 0x50, 0, 0, 0x0000001b },
    { 0x45, 1, 0, 0x00000004 },
    { 0x6, 0, 0, 0x00040000 },
    { 0x6, 0, 0, 0x00000000 },
};

// compare to socket
int init_rawsocket(){
    struct sock_fprog filter;

    filter.len = sizeof(bpf_code)/sizeof(struct sock_filter); 
    filter.filter = bpf_code;

    // initial recv_fd,收到的为以太网帧，帧头长度为18字节
    recv_rawsockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (recv_rawsockfd < 0 ) {
        //perror("socket fail\n");
        printf("recv socket initial failed\n");
        return -1;
    }
    //设置 sk_filter
    if (setsockopt(recv_rawsockfd, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)) < 0) {
        //perror("setsockopt fail\n"); 
        printf("setsockopt fail failed\n");
        return -1;  
    }

    //initial send_fd
    send_rawsockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(send_rawsockfd < 0){
        printf("send socket initial failed\n");
        return -1;
    }
    int one = 1;
    if(setsockopt(send_rawsockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0){   //定义套接字不添加IP首部，代码中手工添加
        printf("setsockopt failed!\n");
        return -1;
    }

    server_addr.sin_family = AF_INET;  
    server_addr.sin_addr.s_addr = inet_addr(REMOTE_ADDR); //设置接收方IP

    return 0;
}

// connect , send TCP-SYN ,wait for TCP-SYN back
int listen_connect(){  
    // recv syn
    int n = recvfrom(recv_rawsockfd, recvbuf, 1024, 0, NULL, NULL); 
    printf("recv a client syn,len %d\n",n);
    // send empty message with ack
    headerinfo h = {inet_addr(LOCAL_ADDR),inet_addr(REMOTE_ADDR),htons(LOCAL_PORT_USED),htons(REMOTE_PORT_USED),0,1,1};
    //h.type = 1; h.seq = 0; h.ack = 1;
    size_t hdrlen;;
    generate_tcp_packet((unsigned char*)sendbuf,hdrlen,h);
    sendto(send_rawsockfd,sendbuf,hdrlen,0,(struct sockaddr *)&server_addr,sizeof(server_addr));  
    printf("send back an ack\n");  
}

int main(int argc,char** argv){
    int ret = init_rawsocket();
    if(ret) printf("init_rawsocket error.");
  //  while(1){
        listen_connect();
   // }
}