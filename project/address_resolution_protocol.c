
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "protocol_util.h"
#include "address_resolution_protocol.h"

struct AddressResolutionProtocolPrimaryHeaderStruct{
	//Page 155 of Intro.ToNetworkSecurity
	unsigned char hardware_type[2]; //Ethernet is 1
	unsigned char protocol_type[2]; //IP is 0x800, 
	unsigned char hardware_length[1]; //Length of hardware address in bytes, Ethernet uses 6
	unsigned char protocol_length[1]; //Length of upper-layer protocol addresses in bytes, IPv4 uses 4
	unsigned char operation[2]; //request = 1, reply = 2
};

union AddressResolutionProtocolPrimaryHeaderUnion{
	struct AddressResolutionProtocolPrimaryHeaderStruct info;
	unsigned char array[8];
};

typedef struct AddressResolutionProtocolFormat * AddressResolutionProtocolFormat_ptr;
struct AddressResolutionProtocolFormat{
	union AddressResolutionProtocolPrimaryHeaderUnion header;
	char * sender_hardware_address;
	char * sender_protocol_address;
	char * target_hardware_address;
	char * target_protocol_address;
	void (*freePacket)(AddressResolutionProtocolFormat_ptr);
};

void freeARPPacket(AddressResolutionProtocolFormat_ptr ptr){
	if(ptr->sender_hardware_address)free(ptr->sender_hardware_address);
	if(ptr->sender_protocol_address)free(ptr->sender_protocol_address);
	if(ptr->target_hardware_address)free(ptr->target_hardware_address);
	if(ptr->target_protocol_address)free(ptr->target_protocol_address);
}

void parseAddressResolutionProtocolFormat(protocol_ptr pptr, char * array){
	int n = 0;
	int hardware_length = 0;
	int protocol_length = 0;
	char buffer[2];
	char *tmp;
	
	AddressResolutionProtocolFormat_ptr ptr;
	confirmProtocol(pptr, "parseAddressResolutionProtocolFormat", ARP);
	ptr = (AddressResolutionProtocolFormat_ptr) pptr->protocol_format;

	if(array == 0 ){
		//fprintf(stderr,"Error:\t%s\n","Null Pointer Exception - parseAddressResolutionProtocolFormat");
		printf("Error:\t%s\n","Null Pointer Exception - parseAddressResolutionProtocolFormat");
		exit(-1);
	}
	
	tmp = array;
	tmp = copy_prefix_safely(1, ptr->header.array,tmp,8);
	
	hardware_length = (int)ptr->header.info.hardware_length[0];
	protocol_length = (int)ptr->header.info.protocol_length[0];
	
	tmp = malloc_copy_prefix(1, &(ptr->sender_hardware_address),tmp,hardware_length);
	tmp = malloc_copy_prefix(1, &(ptr->sender_protocol_address),tmp,protocol_length);
	tmp = malloc_copy_prefix(1, &(ptr->target_hardware_address),tmp,hardware_length);
	tmp = malloc_copy_prefix(1, &(ptr->target_protocol_address),tmp,protocol_length);
	
	ptr->freePacket = &freeARPPacket;
}

void printAddressResolutionProtocolFormat(protocol_ptr pptr, char hex_flag){
	int n = 0;
	char buffer[2];
	int hardware_length = 0;
	int protocol_length = 0;
	
	AddressResolutionProtocolFormat_ptr ptr;
	confirmProtocol(pptr, "printAddressResolutionProtocolFormat", ARP);
	ptr = (AddressResolutionProtocolFormat_ptr) pptr->protocol_format;
	
	if(ptr == 0 ){
		//fprintf(stderr,"Error:\t%s\n","Null Pointer Exception - printAddressResolutionProtocolFormat");
		printf("Error:\t%s\n","Null Pointer Exception - printAddressResolutionProtocolFormat");
		exit(-1);
	}
	
	print_string_safely_with_title(1, "hardware_type", buffer, ptr-> header.info.hardware_type, 2, hex_flag);
	print_string_safely_with_title(1, "protocol_type", buffer, ptr-> header.info.protocol_type, 2, hex_flag);
	print_string_safely_with_title(1, "hardware_length", buffer, ptr-> header.info.hardware_length, 1, hex_flag);
	print_string_safely_with_title(1, "protocol_length", buffer, ptr-> header.info.protocol_length, 1, hex_flag);
	print_string_safely_with_title(1, "operation", buffer, ptr-> header.info.operation, 2, hex_flag);
	
	hardware_length = (int)ptr->header.info.hardware_length[0];
	protocol_length = (int)ptr->header.info.protocol_length[0];
	
	print_string_with_title(1, "sender_hardware_address", ptr->sender_hardware_address, hardware_length, hex_flag);
	print_string_with_title(1, "sender_protocol_address", ptr->sender_protocol_address, protocol_length, hex_flag);
	print_string_with_title(1, "target_hardware_address", ptr->target_hardware_address, hardware_length, hex_flag);
	print_string_with_title(1, "target_protocol_address", ptr->target_protocol_address, protocol_length, hex_flag);
}

void freePacketARP(protocol_ptr pptr){
	AddressResolutionProtocolFormat_ptr ptr;
	if(ptr != 0){
		confirmProtocol(pptr, "printAddressResolutionProtocolFormat", ARP);
		ptr = (AddressResolutionProtocolFormat_ptr) pptr->protocol_format;
		if(ptr != 0){
			ptr->freePacket(ptr);
		}
		free(pptr);
	}
}

void fixPacketARP(protocol_ptr ptr){
}

protocol_ptr initializeAddressResolutionProtocolPacketCommands(){
	protocol_ptr ptr = mallocProtocolTypeStruct(sizeof(struct AddressResolutionProtocolFormat));

	ptr->type		= ARP;
	ptr->print		= &printAddressResolutionProtocolFormat;
	ptr->parse		= &parseAddressResolutionProtocolFormat;
	ptr->freePacket	= &freePacketARP;

	return ptr;
}
