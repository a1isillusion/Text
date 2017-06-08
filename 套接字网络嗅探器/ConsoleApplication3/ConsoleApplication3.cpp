#include"stdafx.h" 
#include"winsock2.h" 
#pragma comment(lib,"Ws2_32.lib") 

typedef struct _TCP
{
	WORD SrcPort;
	WORD DstPort;
	DWORD SeqNum;
	DWORD AckNum;
	BYTE DataOff;
	BYTE Flags;
	WORD Window;
	WORD Chksum;
	WORD UrgPtr;
}TCP;
typedef TCP*LPTCP;

typedef struct _IP
{
	union
	{
		BYTE Version;
		BYTE HdrLen;
	};
	BYTE ServieceType;
	WORD TotalLen;
	WORD ID;
	union
	{
		WORD Flags;
		WORD FragOff;
	};
	BYTE TimeToLive;
	BYTE Protocol;
	WORD HdrChksum;
	DWORD SrcAddr;
	DWORD DstAddr;
	BYTE Options;
}IP;
typedef IP*LPIP;
typedef IP UNALIGNED*ULPIP;
typedef TCP UNALIGNED*ULPTCP;


#define PROTOCOL_STRING_ICMP_TXT "ICMP" 
#define PROTOCOL_STRING_TCP_TXT "TCP" 
#define PROTOCOL_STRING_UDP_TXT "UDP" 
#define PROTOCOL_STRING_UNKNOW_TXT "UNKNOW" 

#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1)  
#define IP_HDRINCL 2 

#define BUFFER_SIZE 65535  

char* GetProtocolText(int);
void PrintHelloMessage();
void main()
{
	PrintHelloMessage();

	WSADATA WSAData;
	SOCKET sock;
	BOOL flag;
	char LocalName[256];
	HOSTENT *pHost;
	SOCKADDR_IN addr_in;
	char RecvBuf[BUFFER_SIZE];
	IP ip;
	TCP tcp;


	WSAStartup(MAKEWORD(2, 2), &WSAData);

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);

	setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char*)&flag, sizeof(flag));

	gethostname((char*)LocalName, sizeof(LocalName) - 1);

	pHost = gethostbyname((char*)LocalName);

	addr_in.sin_addr = *(in_addr*)pHost->h_addr_list[0];
	addr_in.sin_family = AF_INET;
	addr_in.sin_port = htons(50000);

	bind(sock, (LPSOCKADDR)&addr_in, sizeof(addr_in));

	DWORD dwValue = 1;
	ioctlsocket(sock, SIO_RCVALL, &dwValue);

	while (1)
	{
		int ret = recv(sock, RecvBuf, BUFFER_SIZE, 0);
		if (ret>0)
		{
			ip = *(IP*)RecvBuf;
			tcp = *(TCP*)(RecvBuf + ip.HdrLen);

			printf("协议: %s\r\n", GetProtocolText(ip.Protocol));
			printf("IP源地址: %s\r\n", inet_ntoa(*(in_addr*)&ip.SrcAddr));
			printf("IP目标地址: %s\r\n", inet_ntoa(*(in_addr*)&ip.DstAddr));
			printf("TCP源端口: %d\r\n", tcp.SrcPort);
			printf("TCP目标端口:%d\r\n", tcp.DstPort);
			printf("数据包长度: %d\r\n\r\n\r\n", ntohs(ip.TotalLen));
		}
	}
}

char* GetProtocolText(int Protocol)
{
	switch (Protocol)
	{
	case IPPROTO_ICMP:
		return PROTOCOL_STRING_ICMP_TXT;
	case IPPROTO_TCP:
		return PROTOCOL_STRING_TCP_TXT;
	case IPPROTO_UDP:
		return PROTOCOL_STRING_UDP_TXT;
	default:
		return PROTOCOL_STRING_UNKNOW_TXT;
	}
}

void PrintHelloMessage()
{
	printf("-----------------------原始套接字捕获IP包-----------------\n\n");
}

