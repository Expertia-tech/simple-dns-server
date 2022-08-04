// function .c

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include<windows.h>
#include <winsock2.h>
#include "definition.h"
#include <intrin.h>
#include "functions.h"

#pragma comment(lib, "ws2_32.lib") //load ws2_32.dll

// global variable
cache DNSTable[AMOUNT];			//IP domain relation
int IDcount;						//amount of records in IDTransTable
//extern char url[SIZEOFURL];						//url buffer which need to handle


//load local DNS record (dnsrelay.txt)
int InitialDNSTable()
{
	int read = 0;
	int records = 0;
	//char* Temp[AMOUNT];
	FILE* fp = fopen("dnsrelay.txt", "r");
	if (!fp)
	{
		printf("Open file failed!!\n");
		exit(-1);
	}
	while (!feof(fp))
	{
		read = fscanf(fp, "%s %s\n", DNSTable[records].IP, DNSTable[records].domain);
		if (read == 2) {
			// printf("records: %d\n", records);
			records++;
		}

		if (read != 2 && !feof(fp))		// to handle the error if the format in the file is incorrect
		{
			printf("file format incorrect!!\n");
			exit(EXIT_FAILURE);
		}

		if (ferror(fp))
		{
			printf("error reading file!!\n");
			return 1;
			//exit(EXIT_FAILURE);
		}

	}
	/*You Should Realize This Function: Read All Record And Save Them In Global Variable 'DNSTable'.*/

	fclose(fp);
	printf("DNS table loaded sucssfully!!\n");

	return records;
}

//Get url in the DNS packet
void GetUrl(char* recvbuf)
{
	int recvnum = 12;
	char domainName[68];
	ZeroMemory(domainName, 68);
	int i = 0;
	ZeroMemory(&header, sizeof(header));
	memcpy(&header, &recvbuf[0], 12 * sizeof(unsigned short));
	printf("id: %hu   flag: %hu   quesCount: %hu   ansCount: %hu   auth: %hu   arCount: %hu \n", header.id, header.flags, header.quesCount, header.ansCount, header.authRecord, header.arCount);
	// get teh domain name
	while (recvbuf[recvnum] != 0x00)
	{
		if (recvbuf[recvnum] == 0x2D || (recvbuf[recvnum] >= 0x30 && recvbuf[recvnum] <= 0x39) || (recvbuf[recvnum] >= 0x41 && recvbuf[recvnum] <= 0x7A))
			domainName[i] = recvbuf[recvnum];
		else
			domainName[i] = 0x2E;
		recvnum++;
		i++;
	}
	domainName[i] = '\0';
	ZeroMemory(url, SIZEOFURL);
	memcpy(&url, &domainName[1], strlen(domainName));
	url[i] = '\0';
	printf("\nurl %s\n", url);
}


//Try to find the Url in DNSTable. If found, return its subscript, else return NOTFOUND
int IsFound(char* url, int num)
{
	printf("resolving DNS query locally....\n");
	int find = NOTFOUND;

	int i;	// index for iteration
	for (i = 0; i < num; i++)
	{
		//printf("%s\n", DNSTable[i].domain);
		if (strcmp(DNSTable[i].domain, url) == 0)
		{
			printf("found\n");
			printf("found @ isfound at %d\n", i);
			return  i; // atoi(DNSTable[i].IP);	// atoi converts the string to int			
		}
	}

	// if not found in cache
	printf("domain not found in local server\n");
	return find;
}


//DNS Server relay function. It send the request packet to foreign DNS server. When we get response from foreign DNS server, send it back to the client.
int DNSRelay(int recv_flag, char* buf, SOCKADDR_IN clientName, SOCKADDR_IN foreignName, SOCKET localSock, SOCKET foreignSock) {

	/*You Should Realize This Functiion: send the packet to foreign DNS server, get the response packet, send it back to client.*/

	SOCKADDR_IN serverResponse;	// use to hold the client information (port/ ip address)
	int serverResponseLength = sizeof(serverResponse);
	char sendBuf[BUF_SIZE];
	ZeroMemory(sendBuf, BUF_SIZE);
	//strcpy(sendBuf, buf);

	//send the packet to foreign DNS server
	int serverName_size = sizeof(foreignName);
	printf("sizeof @ relay %d\n", serverName_size);

	int send_flag = sendto(foreignSock, buf, recv_flag, 0, (SOCKADDR*)&foreignName, serverName_size);
	printf("send_flag @ dnsrelay: %d\n", send_flag);
	if (send_flag == SOCKET_ERROR)
	{
		printf("send failed!!\n");
		return -1;
	}
	else
		printf("request sent to foreign DNS!\n");

	//ZeroMemory(buf, BUF_SIZE);
	//receive respond from foreign DNS server
	ZeroMemory(sendBuf, BUF_SIZE);
	int clientName_size = sizeof(clientName);
	recv_flag = recvfrom(foreignSock, sendBuf, BUF_SIZE, 0, (SOCKADDR*)&serverResponse, &serverResponseLength);
	if (recv_flag < 0) {
		printf("recvfrom() failed!!\n");
		return -1;
	}
	else
		printf("packet received from foreign DNS!\n");
	//printf("%s", buf);

	//Send the respond packet back
	send_flag = sendto(localSock, sendBuf, BUF_SIZE, 0, (SOCKADDR*)&clientName, clientName_size);
	if (send_flag == SOCKET_ERROR)
	{
		printf("send failed!\n");
		return -1;
	}
	else
		printf("packet sent to client: OK\n");

	return send_flag;
}


//DNS Server respond function. It make a respond DNS header, fill all the field in the header, construct the resource and the header, make it a whole DNS respond packet, then send it back to the client.
int DNSRespond(int find_flag, int recv_flag, char* buf, SOCKADDR_IN clientName, SOCKET localSock) {
	char sendBuf[BUF_SIZE];
	ZeroMemory(sendBuf, BUF_SIZE);
	/*You Should Realize This Functiion: Build your own DNS response packet, and send it back to client.*/

	int rspMsgSize;
	//NOTICE: For normal IP and blocked IP, the DNS packet should be different.
	//For normal IP, the return code should be 0, which means NOERROR.
	//For blocked IP, the return code should be 3, which means NXDOMAIN, and should have no answer resource.
	int pos = 0;
	memcpy(&sendBuf[pos], buf, recv_flag);
	unsigned short flag = htons(0x8180);

	memcpy(&sendBuf[2], &flag, sizeof(flag));

	//change AnswerNum field.
	unsigned short answerNum;
	if (strcmp(DNSTable[find_flag].IP, "0.0.0.0") == 0) {
		answerNum = htons(0x0000);	//when blocked, get no resource

		return 0;
	}
	else {
		answerNum = htons(0x0001);	//when normal, get 1 resource

	}
	memcpy(&sendBuf[6], &answerNum, sizeof(answerNum));

	int i = 12;
	pos = recv_flag;
	while (buf[i] != 0x00) { /*the domain name zone*/
		sendBuf[pos] = buf[i];
		pos++;
		i++;
	}

	sendBuf[pos] = 0x00;
	pos++;
	// answer
	unsigned short qtype = htons(0x0001);
	unsigned short qclass = htons(0x0001);
	unsigned int ttl = htonl(0x00015180);
	unsigned short datalen = htons(0x0004);
	unsigned int ipAddr = inet_addr(DNSTable[find_flag].IP);

	memcpy(&sendBuf[pos], &qtype, sizeof(unsigned short)); /*the type zone*/
	pos = pos + sizeof(unsigned short);
	memcpy(&sendBuf[pos], &qclass, sizeof(unsigned short)); /*the classes zone*/
	pos = pos + sizeof(unsigned short);
	memcpy(&sendBuf[pos], &ttl, sizeof(unsigned int)); /*the ttl zone*/
	pos = pos + sizeof(unsigned int);
	memcpy(&sendBuf[pos], &datalen, sizeof(unsigned short)); /*the data length*/
	pos = pos + sizeof(unsigned short);
	memcpy(&sendBuf[pos], &ipAddr, sizeof(unsigned int)); /*the ip address*/
	rspMsgSize = pos + sizeof(unsigned int);

	printf("respond : %s", sendBuf);
	//sending DNS respond packet
	int send_flag = sendto(localSock, sendBuf, rspMsgSize, 0, (SOCKADDR*)&clientName, sizeof(clientName));
	return send_flag;//send_flag;
}




int serverStartUp(SOCKET localSock, SOCKET foreignSock, SOCKADDR_IN foreignName, int recordNum)
{
	SOCKADDR_IN client;	// use to hold the client information (port/ ip address)
	int clientLength = sizeof(client);

	int find_flag;		//return value of IsFound()
	int recv_flag;		//return value of recvfrom()
	int relay_flag;
	int respond_flag;
	char clientIp[256]; // Create enough space to convert the address byte array
	ZeroMemory(clientIp, 256); // to string of characters
	char buf[BUF_SIZE];

	// enter a loop
	while (1)
	{
		ZeroMemory(&client, clientLength);	// clear the client structure
		ZeroMemory(buf, BUF_SIZE);	// clear the receive buffer everytime before receiving new message

		// wait for message
		recv_flag = recvfrom(localSock, buf, BUF_SIZE, 0, (SOCKADDR*)&client, &clientLength);
		printf("recv_flag first: %d", recv_flag);
		if (recv_flag == SOCKET_ERROR)
		{
			printf("ERROR receiving from client!\n");
			WSAGetLastError();
			continue;
		}

		// Display message and client info
		ZeroMemory(clientIp, 256); // to string of characters

		// convert from byte array to chars
		inet_ntop(AF_INET, &client.sin_addr, clientIp, 256);



		//get the url
		GetUrl(buf);

		// Display the message / who sent it
		printf("message received from  %s  %s\n\n", clientIp, url);

		//try to find the url
		find_flag = IsFound(url, recordNum);
		printf("find_flag after isfound: %d\n", find_flag);
		if (find_flag == NOTFOUND)	 // execute the relay function if the domain is not found
		{
			relay_flag = DNSRelay(recv_flag, buf, client, foreignName, localSock, foreignSock);
			if (relay_flag == SOCKET_ERROR) continue;
			else if (relay_flag == 0) break;
		}	// relayed
		else	// respond
		{
			respond_flag = DNSRespond(find_flag, recv_flag, buf, client, localSock);
			if (respond_flag == SOCKET_ERROR) continue;
			else if (respond_flag == 0) break;
		}	//responded
	}
	return 0;
}