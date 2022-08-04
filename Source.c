#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#pragma comment(lib, "ws2_32.lib") //load ws2_32.dll

#include <WinSock2.h>
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <string.h>
#include "definition.h"
#include "functions.h"


//const char url[SIZEOFURL];


int main()
{
	WSADATA wsaData;
	int iResult;	// stores the return value from WSAStartup for error handling

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0)
	{
		printf("WSAStartup failed: %d\n", iResult);	   // cant start winshock
		return 1;
	}

	// create socket
	SOCKET localSock = socket(AF_INET, SOCK_DGRAM, 0);		// SOCK_DGRAM for udp, Protocol set to 0 means default protocol for the address family. 
	if (localSock < 0)
	{
		printf("socket creation failed!!!\n\n");
		exit(EXIT_FAILURE);
	}

	SOCKET foreignSock = socket(AF_INET, SOCK_DGRAM, 0); // AF_INET - using IPv4 protocal; SOCK_DGRAM - using datagram; IPPROTO_UDP-using UDP protocal
	if (foreignSock < 0)
	{
		printf("socket creation failed!!!\n\n");
		exit(EXIT_FAILURE);
	}


	// get server info
	HOSTENT* host = gethostbyname(url);
	if (host == NULL)
	{
		exit(EXIT_FAILURE);
	}

	// define server info for the server
	// basically binding the socket to the ip address that we want to use 
	SOCKADDR_IN local_server_address;
	ZeroMemory(&local_server_address, sizeof(local_server_address));	// similar to memset 0, since we are not using all the bytes of the struct
	local_server_address.sin_port = htons(DNS_SERVICE_PORT);
	//convert an IP port number in host byte order to the IP port number in network byte order.
	local_server_address.sin_family = AF_INET;	  // AF_INET for IPv4
	local_server_address.sin_addr.s_addr = inet_addr(LOCAL_DNS_ADDRESS);	//binding IP address

	// defining server info for client, we use the user's API
	SOCKADDR_IN foreignName;
	foreignName.sin_family = AF_INET;
	foreignName.sin_port = htons(DNS_SERVICE_PORT);
	foreignName.sin_addr.s_addr = inet_addr(DEF_DNS_ADDRESS);


	//load dnsrelay.txt to DNSTable 
	//char Path[100];
	//strcpy(Path, "dnsrelay.txt");
	int recordNum = InitialDNSTable();
	printf("total records in cache: %d\n", recordNum);

	// bind the socket with the server address
	if (bind(localSock, (SOCKADDR*)&local_server_address, sizeof(local_server_address)))
	{
		printf("Bind 53 port failed.\n");
		exit(-1);
	}
	else
		printf("Bind 53 port success.\n");

	// execute DNS server main loop
	serverStartUp(localSock, foreignSock, foreignName, recordNum);
	printf("server start up: success\n");

	closesocket(foreignSock);
	closesocket(localSock);
	WSACleanup(); // release ws2_32.dll

	return 0;
}