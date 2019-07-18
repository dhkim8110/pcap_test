#ifndef _PACAP_H
#define _PACAP_H

#define ETHER_ADDR_LEN 6
#define SIZE_ETHERNET 14

#define IP_V(ip) (((ip)->ip_vhl) >> 4)      //IP버전 길이
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)   //IP헤더 길이

#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>  // inet_ntoa
#include <netinet/in.h> // in_addr


//패킷 변수 선언
struct pcap_pkthdr* header;   //패킷 헤더 정보
const u_char* packet;         //패킷 데이터 정보
char *filter_exp = "port 80"; // 포트 지정
struct bpf_program fp;        // 필터 구조체
bpf_u_int32 net;              // 아이피 주소
struct in_addr addr;          // 주소 정보
typedef u_int tcp_seq;        //tcp_seq

//Ethernet 구조체 선언
struct ethernet {
    u_char ether_shost[ETHER_ADDR_LEN]; // Smac 6byte
    u_char ether_dhost[ETHER_ADDR_LEN]; // Dmac 6byte
    u_short ether_type;                 // type 2byte
 };/*total: 14byte */

//IP 구조체 선언
struct ip {
        u_char ip_vhl;            //IP 버전, 헤더 길이
        u_char ip_tos;            //IP 타입
        u_short ip_len;           //IP 길이 값
        u_short ip_id;            //IP 아이디
        u_short ip_off;           //Fragment offset
        #define IP_RF 0x8000      //
        #define IP_DF 0x4000
        #define IP_MF 0x2000
        #define IP_OFFMASK 0x1fff
        u_char ip_ttl;
        u_char ip_p;              // IP 프로토콜 유형
        u_short ip_sum;           //checksum
        struct in_addr ip_src; // 출발지 IP 주소
        struct in_addr ip_dst; // 목적지 IP 주소
};

//TCP 구조체 선언
struct tcp {
        u_short th_sport; // 출발지 TCP 주소
        u_short th_dport; // 목적지 TCP 주소
        tcp_seq th_seq;
        tcp_seq th_ack;
        u_char th_offx2;
        #define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
        u_char th_flags;
        #define TH_FIN 0x01
        #define TH_SYN 0x02
        #define TH_RST 0x04
        #define TH_PUSH 0x08
        #define TH_ACK 0x10
        #define TH_URG 0x20
        #define TH_ECE 0x40
        #define TH_CWR 0x80
        #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;
        u_short th_sum;
        u_short th_urp;
};


#endif // _PACAP_H
