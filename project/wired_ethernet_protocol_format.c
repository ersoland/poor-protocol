
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "protocol_util.h"
#include "wired_ethernet_protocol_format.h"

typedef struct WiredFrameFormat * WiredFrameFormat_ptr;
struct WiredFrameFormat{
	//Page 99 of Intro.ToNetworkSecurity
	unsigned char preamble[7];
	unsigned char start_frame_delimiter[1];
	unsigned char destination_address[6];
	unsigned char source_address[6];
	//If greater than 1536 (0x600), it is a type field
		//0x800 - IP protocol
		//0x806 - ARP protocol
		//0x86dd - IPv6 protocol
	//If less than 1518, it is a length field
		//46-1500 bytes
	unsigned char type_length_field[1];
	unsigned char data[1500]; //46 to 1500 bytes
	unsigned char frame_check_sequence[4];
};


void parseWiredFrameFormat(protocol_ptr pptr, char * array){
	int n = 0;
	int data_len = 0;
	char *tmp;

	confirmProtocol(pptr,"parseWiredFrameFormat", WIRED);

	WiredFrameFormat_ptr ptr = (WiredFrameFormat_ptr) pptr->protocol_format;

	if(array == 0 ){
		//fprintf(stderr,"Error:\t%s\n","Null Pointer Exception - parseWirelessFrameFormat");
		printf("Error:\t%s\n","Null Pointer Exception - parseWirelessFrameFormat");
		exit(-1);
	}
	
	//char *strncpy(char *dest, const char *src, size_t n)
	
	tmp = array;
	tmp = copy_prefix_safely(1, ptr-> preamble,tmp,7);
	tmp = copy_prefix_safely(1, ptr-> start_frame_delimiter,tmp,1);
	tmp = copy_prefix_safely(1, ptr-> destination_address,tmp,6);
	tmp = copy_prefix_safely(1, ptr-> source_address,tmp,6);
	tmp = copy_prefix_safely(1, ptr-> type_length_field,tmp,1);
	tmp = copy_prefix_safely(0, ptr-> data,tmp,1500);
	//printf("\ndata=[%s] tmp=[%s]\n",ptr-> data,tmp);
	tmp = copy_prefix_safely(1, ptr-> frame_check_sequence,tmp,4);
}

void printWiredFrameFormat(protocol_ptr pptr, char hex_flag){
	int n = 0;
	char buffer[2048];

	confirmProtocol(pptr,"printWiredFrameFormat", WIRED);
	WiredFrameFormat_ptr ptr = (WiredFrameFormat_ptr) pptr->protocol_format;

	if(ptr == 0 ){
		//fprintf(stderr,"Error:\t%s\n","Null Pointer Exception - printWirelessFrameFormat");
		printf("Error:\t%s\n","Null Pointer Exception - printWirelessFrameFormat");
		exit(-1);
	}
	
	print_string_safely_with_title(1, "preamble",buffer,ptr-> preamble,7,hex_flag);
	print_string_safely_with_title(1, "start_frame_delimiter",buffer,ptr-> start_frame_delimiter,1,hex_flag);
	print_string_safely_with_title(1, "destination_address",buffer,ptr-> destination_address,6,hex_flag);
	print_string_safely_with_title(1, "source_address",buffer,ptr-> source_address,6,hex_flag);
	print_string_safely_with_title(1, "type_length_field",buffer,ptr-> type_length_field,1,hex_flag);
	print_string_safely_with_title(0, "data",buffer,ptr-> data,1500,hex_flag);
	print_string_safely_with_title(1, "frame_check_sequence",buffer,ptr-> frame_check_sequence,4,hex_flag);
}

void freePacketWEP(protocol_ptr pptr){
	confirmProtocol(pptr,"Wired freePacket", WIRED);
	if(pptr != 0) free(pptr);
}

protocol_ptr initializeWiredEthernetPacketCommands(){
	protocol_ptr ptr = mallocProtocolTypeStruct(sizeof(struct WiredFrameFormat));

	ptr->type		= WIRED;
	ptr->print		= &printWiredFrameFormat;
	ptr->parse		= &parseWiredFrameFormat;
	ptr->freePacket	= &freePacketWEP;

	return ptr;
}

