#ifndef FUNCTIONS_H_INCLUDED
#define FUNCTIONS_H_INCLUDED

#pragma once

 char url[SIZEOFURL];						//url buffer which need to handle
 dnsHeader header;

int InitialDNSTable(); 
/**
	* Load local DNS records from path(dnsrelay.txt).
**/


void GetUrl(char* recvbuf);
/**
	* Get url in the DNS packet
	* Read the Packet in recvbuf, pick the Url out, and save it in Global Variable 'Url'.
	* here recvnum will be the size of the dns header.
**/


int IsFound(char *buf, int num);
/**
	* Try to find the Url in DNSTable. If founded, return its subscript, else return NOTFOUND
	* You Should Realize This Functiion: Try to find the Url in DNSTable. If founded, return its subscript, else return NOTFOUND
**/	

int DNSRelay( int recv_flag, char* recvBuf, SOCKADDR_IN clientName, SOCKADDR_IN foreignName, SOCKET localSock, SOCKET foreignSock);
//DNS Server relay function. It change the ID of the request packet, and send it to foreign DNS server. When it get respond from foreign DNS server, 
//it change the ID of the respond packet, and send it back to the client


int DNSRespond(int find_flag, int recv_flag, char *recvBuf, SOCKADDR_IN clientName, SOCKET localSock);
/*
	* It make a respond DNS header, fill all the field in the header, 
	* construct the resource and the header, make it a whole DNS respond packet,
	* send it back to the client.

*/


int serverStartUp(SOCKET localSock, SOCKET foreignSock, SOCKADDR_IN foreignName, int recordNum);
/**
	* starts up the server
	* receives packets from the client 
	* loads up the buffer. basically gets the url 
	* finds the url in cache
	* respond if the url is found in cache
	* else relay get the respond then respond back to the client 
**/

#endif   // FUNCTIONS_H_INCLUDED