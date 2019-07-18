#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>  // inet_ntoa
#include <netinet/in.h> // in_addr
#include "_pacap.h"


void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  // argc 장치 받아오기 실패시 -1 리턴
  if (argc != 2) {
    usage();
    return -1;
  }

  // 장치변수, 에러저장 변수 선언
  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];

  //네트워크 상의 패킷 동적으로 읽음
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);


  //디바이스 열기 없을 경우 -1리턴 후 종료
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  //while로 패킷정보 읽어오기
  while (true) {
      //구조체 포인터 선언
      struct ethernet *ethernet;    // Ethernet Header
      struct ip *ip;                // IP Header
      struct tcp *tcp;              // TCP Header

      //크기 저장 변수 선언언
      char *payload;                // Payload
      u_int size_ip;                // IP size
      u_int size_tcp;               // tcp size

    //동적 패킷정보 읽기 packet에 저장, handle에 에러정보 저장
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    //패킷정보 출력
    /*
    printf("len: %u bytes captured\n", header->caplen);
    printf("Mac : %u\n", header->len);
    printf("IP : %u\n", packet);
    */

    printf("------------------------------------------------------\n");
            int i, payload_len;

            //Ethernet 출력
            /*패킷 최초 6자리 dmac, 다음 6자리 smac, 마지막 2자리 타입 총 14자리  */
            ethernet = (struct ethernet*)(packet);
            printf("eth.smac : ");
            for(i = 0; i < ETHER_ADDR_LEN; i++) {
                    printf("%02x ", ethernet->ether_shost[i]); //ethernet 변수에 packet에의 값저장하여 출력
            }
            printf("\neth.dmac : ");
            for(i = 0; i < ETHER_ADDR_LEN; i++) {
                    printf("%02x ", ethernet->ether_dhost[i]);
            }

            //IP위치 => packet + 이더넷 길이(14)
            ip = (struct ip*)(packet + SIZE_ETHERNET);
            size_ip = IP_HL(ip)*4; //IP header_length
            printf("\nip.sip : %s ", inet_ntoa(ip->ip_src)); //ntoa network byte order를 address 형태(정수.)로 변환
            printf("\nip.dip : %s", inet_ntoa(ip->ip_dst));  //netword패킷(빅엔디안) -> CPU(리틀엔디안) 출력

            //TCP위치 => packet + 이더넷 길이 + IP길이
            tcp = (struct tcp*)(packet + SIZE_ETHERNET + size_ip);
            size_tcp = TH_OFF(tcp)*4; //offset
            printf("\ntcp.sport : %d ", ntohs(tcp->th_sport)); //ntohs network byte order를 host byte order로 변환
            printf("\ntcp.dport : %d ", ntohs(tcp->th_dport));

            //Data위치 => packet + 이더넷 길이 + IP길이 + TCP길이
            payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

            //Data길이 출력
            payload_len = ntohs(ip->ip_len) - (size_ip + size_tcp);
            if(payload_len == 0){
                printf("\ndata가 없습니다.");
            }else {
                printf("\n< data >\n");
                //payload_len 길이를 10byte만큼 출력
                for(int i = 0; i < 10; i++) {
                   printf("%02x ", payload[i]);
                   //if(i % 8 == 0) printf("  ");
                   //if(i % 16 == 0) printf("\n");
                }
            }
            printf("\n------------------------------------------------------\n\n");
  }

  //pcap 종료
  pcap_close(handle);
  return 0;
}
