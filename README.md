# 공부내용


![Packet 구조](https://user-images.githubusercontent.com/52531056/61441680-17ff6680-a981-11e9-9200-6559023c56ca.jpg)



# 디버깅 추가(tcp-port-80-test.gilgil)
![pcap_test_김도현](https://user-images.githubusercontent.com/52531056/61533150-ed87d900-aa66-11e9-8bbe-4313c819ec2e.PNG)





구조체 예시)

struct Person {    
    char name[20];         
    int age;              
   char address[100];    
};

struct Person *p1 = malloc(sizeof(struct Person));

구조체의 포인터 변수 동적선언.


p1 -> name식으로 구조체의 멤버변수에 참조
(*p1).name랑 같음.


Packet을 pcap_next_ex로 동적으로 긁어와 저장
ethernet, IP, TCP, payload(데이터)를 각각 구조체로 선언(각 필드 영역을 모두 선언함)
ethernet는 6,6,2 총 14byte 영역 현 과제에서는 앞에 smac, dmac만 출력

IP는 과제에서 source, destination만 출력하기 때문에 받아온 packet에서
ethernet의 길이만큼 더하고 ip의 필요없는 부분들을 더하면 뒤에 source, destination만 출력 가능

TCP는 과제에서 sport,dport만 출력 TCP 헤더의 맨 처음에 바로 위치
packet + ethernet + IP길이 만큼 더하여 바로 출력가능

Data, payload 영역은 packet에서 ethernet, IP, TCP의 길이를 더하여 위치 구하는게 가능
for문으로 10byte만 출력
별도의 배열선언으로 값을 계산하여 출력하지 않고 ntoa(network를 주소형태 (정수.)으로 변환)
ntoh를 써서 네트워크 빅엔디안 전송에서 CPU 리틀엔디안 구조로 변환함.


# 성과.
IP, TCP 구조체의 사용하지 않은 멤버변수들이 정확히 무슨 역할인지는 파악 못했지만,
구조체 포인터의 사용법을 익히고 패킷의 구조를 파악할 수 있었다.
wireshark사용 없이 pcap를 사용하여 동적으로 패킷을 불러와 각 필드에 대하여 학습하였다.

