#ifndef DEFINITION_H_INCLUDED
#define DEFINITION_H_INCLUDED

#pragma once


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <WinSock2.h>
#include <windows.h>
#include <time.h>


// macro 
#define DNS_SERVICE_PORT 53				 //The port DNS protocol use. To DNS server it must be 53. To DNS client, it can be a random port from 1024 to 65535.
#define SIZEOFURL 64					 //A length defination of url buffer size. Used in global variable "Url".
#define DEF_DNS_ADDRESS "192.168.1.254"	 // router
#define LOCAL_DNS_ADDRESS "127.0.0.1"	 // host
#define AMOUNT 1500						 //Maximum rows IDTranstable buffer can hold. Set 1500
#define BUF_SIZE 1024					 // size of the buffer for the message received from the client
#define NOTFOUND 32767					 //A flag defination used in function "IsFound"

// for the response 
typedef struct {
	unsigned short  id;			/* Randomly chosen identifier */
	unsigned short  flags;		/* Bit-mask to indicate request/response */
	unsigned short  quesCount;	/* Number of questions */
	unsigned short  ansCount;	/* Number of answers */
	unsigned short  authRecord;	/* Number of authority records */
	unsigned short  arCount;		/* Number of additional records */
}dnsHeader;


// data structures
typedef struct translate
/**
	* A record of the relation between domainand its ipv4 address.
	* to load the records into the server in table
	* cache: an alias of the struct translate
**/
{
	char IP[256];						//IP address
	char domain[255];					//domain
} cache;


#endif // DEFINITION_H_INCLUDED