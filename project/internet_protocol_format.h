#ifndef IP_H
#define IP_H

#include "protocol_util.h"

struct svnahl_ers{
	unsigned char header_length : 4;
	unsigned char version_number : 4;
};

union uvnahl_ers{
	unsigned char str[1];
	unsigned char byte;
	struct svnahl_ers nibbles;
};

struct floffs_ers{
	unsigned short flags : 3;
	unsigned short offset : 13;
};

union floffu_ers{
	unsigned char str[2];
	struct floffs_ers parts;
	short word;
};

struct IPPacketHeader{
	union uvnahl_ers version;
	unsigned char type_of_service[1];
	unsigned char length[2]; //Payload Length
	unsigned char identifier[2];
	union floffu_ers flags;
	unsigned char time_to_live[1];//TTL
	unsigned char protocol[1]; //1 for ICMP, 6 for TCP, 17 for UDP
	unsigned char checksum[2]; //error detection
	unsigned char source_IP_address[4];
	unsigned char destination_IP_address[4];
};

typedef union {
	struct IPPacketHeader info;
	char array[20];
}IPPacketHeaderUnion;

typedef struct IPPacketFormat * IPPacketFormat_ptr;
struct IPPacketFormat{
	//Page 149 of Intro.ToNetworkSecurity
	IPPacketHeaderUnion header;
	char blank[8];
	char * options;//All bytes after 20 until header_length
	char * data; //65536-header length
	//Is initialized in parsing method
	void (*freePacket)(IPPacketFormat_ptr);
};

void parseIPPacketFormat(protocol_ptr pptr, char * array);

void printIPPacketFormat(protocol_ptr pptr, char hex_flag);

void printIPPacketFormatAsIP(IPPacketFormat_ptr ptr, char hex_flag, char blank_field_flag);

void freePacketIPF(protocol_ptr pptr);

void fixPacketIPF(protocol_ptr ptr);

protocol_ptr initializeInternetProtocolPacketCommands();

#endif
