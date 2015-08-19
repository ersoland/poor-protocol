
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "protocol_util.h"
#include "wireless_ethernet_protocol_format.h"

typedef struct WirelessFrameFormat * WirelessFrameFormat_ptr;
struct WirelessFrameFormat{
	//Page 113 of Intro.ToNetworkSecurity
	unsigned char frame_control[7];
	unsigned char duration_id[1];
	unsigned char address_1[6];//_destination_controller_address; 
	unsigned char address_2[6];//_transmitting_device_address;
	unsigned char address_3[6];//_traffic_relay_address;
	unsigned char sequence_control[2];
	unsigned char address_4[6];//_traffic_relay_address;
	//No minumum- max size is 2312 bytes
	unsigned char data[2312];
	unsigned char frame_check_sequence[4];
};

void parseWirelessFrameFormat(protocol_ptr pptr, char * array){
	int n = 0;
	int data_len = 0;
	char *tmp;

	confirmProtocol(pptr,"parseWirelessFrameFormat",WIRELESS);
	
	WirelessFrameFormat_ptr ptr = (WirelessFrameFormat_ptr) pptr->protocol_format;

	if(array == 0 ){
		//fprintf(stderr,"Error:\t%s\n","Null Pointer Exception - parseWirelessFrameFormat");
		printf("Error:\t%s\n","Null Pointer Exception - parseWirelessFrameFormat");
		exit(-1);
	}
	
	//char *strncpy(char *dest, const char *src, size_t n)
	
	tmp = array;
	tmp = copy_prefix_safely(1, ptr-> frame_control,tmp,7);
	tmp = copy_prefix_safely(1, ptr-> duration_id,tmp,1);
	tmp = copy_prefix_safely(1, ptr-> address_1,tmp,6);
	tmp = copy_prefix_safely(1, ptr-> address_2,tmp,6);
	tmp = copy_prefix_safely(1, ptr-> address_3,tmp,6);
	tmp = copy_prefix_safely(1, ptr-> sequence_control,tmp,2);
	tmp = copy_prefix_safely(1, ptr-> address_4,tmp,6);
	tmp = copy_prefix_safely(0, ptr-> data,tmp,2312);
	tmp = copy_prefix_safely(1, ptr-> frame_check_sequence,tmp,4);
}

void printWirelessFrameFormat(protocol_ptr pptr, char hex_flag){
	int n = 0;
	char buffer[4096];
	
	confirmProtocol(pptr,"printWirelessFrameFormat",WIRELESS);

	WirelessFrameFormat_ptr ptr = (WirelessFrameFormat_ptr) pptr->protocol_format;

	if(ptr == 0 ){
		//fprintf(stderr,"Error:\t%s\n","Null Pointer Exception - printWirelessFrameFormat");
		printf("Error:\t%s\n","Null Pointer Exception - printWirelessFrameFormat");
		exit(-1);
	}
	
	print_string_safely_with_title(1, "frame_control",buffer,ptr-> frame_control,7,hex_flag);
	print_string_safely_with_title(1, "duration_id",buffer,ptr-> duration_id,1,hex_flag);
	print_string_safely_with_title(1, "address_1",buffer,ptr-> address_1,6,hex_flag);
	print_string_safely_with_title(1, "address_2",buffer,ptr-> address_2,6,hex_flag);
	print_string_safely_with_title(1, "address_3",buffer,ptr-> address_3,6,hex_flag);
	print_string_safely_with_title(1, "sequence_control",buffer,ptr-> sequence_control,2,hex_flag);
	print_string_safely_with_title(1, "address_4",buffer,ptr-> address_4,6,hex_flag);
	print_string_safely_with_title(0, "data",buffer,ptr-> data,2312,hex_flag);
	print_string_safely_with_title(1, "frame_check_sequence",buffer,ptr-> frame_check_sequence,4,hex_flag);
}

void freePacketWLF(protocol_ptr ptr){
	if(ptr != 0) free(ptr);
}


protocol_ptr initializeWirelessEthernetPacketCommands(){
	protocol_ptr ptr = mallocProtocolTypeStruct(sizeof(struct WirelessFrameFormat));

	ptr->type		= WIRELESS;
	ptr->print		= &printWirelessFrameFormat;
	ptr->parse		= &parseWirelessFrameFormat;
	ptr->freePacket	= &freePacketWLF;

	return ptr;
}
