
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "protocol_util.h"
#include "internet_control_messaging_protocol.h"
#include "internet_protocol_format.h"

struct id_sequence_parameters{
	unsigned char identification[2];
	unsigned char sequence_number[2];
};

union parameter_union{
	struct id_sequence_parameters params;
	unsigned char new_router_IP_address[4];
};

struct timestamp{
	unsigned char original_timestamp[4];
	unsigned char recieve_timestamp[4];
	unsigned char transmit_timestamp[4];
};

union information_union{
	//(type:code) => (3:1-15), (11:0,1), (5:0-3)
	//Original IP header (4 bytes * 5 = 20) plus 8 bytes of payload
	unsigned char str[28];
	//(type:code) => (14-13:0)
	struct timestamp time;
	struct IPPacketFormat ip;
};

union information_ptr{
	union information_union * union_ptr;
	//Type = 0 or 8, and Code = 0
	char * user_specified;
	IPPacketFormat_ptr ip_ptr;
};

struct primary_header_struct{
	unsigned char type[1];
	unsigned char code[1];
	unsigned char checksum[2];
};

union primary_header_union{
	struct primary_header_struct info;
	char str[4];
};

typedef struct InternetControlMessagingProtocolFormat * InternetControlMessagingProtocolFormat_ptr;
struct InternetControlMessagingProtocolFormat{
	//Page 156 of Intro.ToNetworkSecurity
	union primary_header_union head;
	union parameter_union parameter;
	union information_ptr info_ptr;
	void (*freePacket)(InternetControlMessagingProtocolFormat_ptr);
};

/////////////////////////////////////////////////////////////////////////////////////////////////////

void freeICMPPacket(InternetControlMessagingProtocolFormat_ptr ptr){
	if(ptr->info_ptr.user_specified)free(ptr->info_ptr.user_specified);
}

void fixIPPacketInICMPPacket(InternetControlMessagingProtocolFormat_ptr ptr){
	int length = 0;
	
	length = ptr->info_ptr.ip_ptr->header.info.version.nibbles.header_length;
	if(length == 5){
		ptr->info_ptr.ip_ptr->options = 0;
		ptr->info_ptr.ip_ptr->data = &(ptr->info_ptr.ip_ptr->blank[0]);
	}else if(length == 6){
		ptr->info_ptr.ip_ptr->options = &(ptr->info_ptr.ip_ptr->blank[0]);
		ptr->info_ptr.ip_ptr->data = &(ptr->info_ptr.ip_ptr->blank[4]);
	}else if(length > 6){
		ptr->info_ptr.ip_ptr->options = &(ptr->info_ptr.ip_ptr->blank[0]);
		ptr->info_ptr.ip_ptr->data = 0;
	}else {
		ptr->info_ptr.ip_ptr->options = 0;
		ptr->info_ptr.ip_ptr->data = 0;
	}
}

struct code_struct{
	unsigned char isZero : 1;
	unsigned char isBetween1and15 : 1;
	unsigned char isZeroOrOne : 1;
	unsigned char isZeroToThree : 1;
};

union code_union{
	struct code_struct flags;
	unsigned char value;
};

int getModifiedCode(int type, int code){
	
	union code_union flags;
	unsigned int new_code = 0;
	unsigned int tmp_code = 0;
	flags.value = 0;
	const int prime = 499; //should be bigger than 256 and preferably prime
	
	/* //Done in excel
type\code	7		8		12		14
0		3493*	3992	5988	6986
8		3501*	4000	5996	6994
13		3506*	4005	6001	6999
14		3507*	4006	6002	7000
3		3496	3995*	5991*	6989*
11		3504*	4003	5999	6997*
5		3498*	3997	5993*	6991*
	*/
	
	if(code == 0){
		flags.flags.isZero = 1;
	}
	if(code <= 15 && code >= 1){
		flags.flags.isBetween1and15 = 1;
	}
	if(code == 0 || code == 1){
		flags.flags.isZeroOrOne = 1;
	}
	if(code <= 3 && code >= 0){
		flags.flags.isZeroToThree = 1;
	}
	
	new_code = (unsigned int)flags.flags.isZero;
	tmp_code = (unsigned int)flags.flags.isZeroOrOne;
	new_code = new_code | (tmp_code << 1);
	tmp_code = (unsigned int)flags.flags.isZeroToThree;
	new_code = new_code | (tmp_code << 2);
	tmp_code = (unsigned int)flags.flags.isBetween1and15;
	new_code = new_code | (tmp_code << 3);
	//printf("flags = %d, new_code = %d, result = %d\n",flags.value,new_code,(new_code*prime+type));
	
	return new_code*prime+type;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////

void parseInternetControlMessagingProtocolFormat(protocol_ptr pptr, char * array){
	int n = 0;
	unsigned int type = 0;
	unsigned int code = 0;
	unsigned int new_code = 0;
	union code_union flags;
	char buffer[4];
	char *tmp;
	int length = 0;
	
	flags.value = 0;
	
	InternetControlMessagingProtocolFormat_ptr ptr;
	confirmProtocol(pptr, "parseInternetControlMessagingProtocolFormat", ICMP);
	ptr = (InternetControlMessagingProtocolFormat_ptr) pptr->protocol_format;
	
	if(ptr == 0 ){
		ptr = malloc(sizeof(struct InternetControlMessagingProtocolFormat));
	}
	if(array == 0 ){
		//fprintf(stderr,"Error:\t%s\n","Null Pointer Exception - parseAddressResolutionProtocolFormat");
		printf("Error:\t%s\n","Null Pointer Exception - parseAddressResolutionProtocolFormat");
		exit(-1);
	}
	
	tmp = array;
	tmp = copy_prefix_safely(1, ptr->head.str,tmp,4);
	tmp = copy_prefix_safely(1, ptr->parameter.new_router_IP_address,tmp,4);
	
	type = (unsigned int) ptr->head.info.type[0];
	code = (unsigned int) ptr->head.info.code[0];
	new_code = getModifiedCode(type, code);
	
	switch(new_code){
		case 3501:
		case 3493:
			//0, 8
			tmp = malloc_copy_prefix(0, &(ptr->info_ptr.user_specified),tmp,4096);
			break;
		case 3506:
		case 3507:
			//13, 14
			tmp = malloc_copy_prefix(1, &(ptr->info_ptr.user_specified),tmp,12);
			break;
		case 3995://3
		case 5991://3
		case 6989://3
		case 3504://11
		case 6997://11
		case 3498://5
		case 5993://5
		case 6991://5
			tmp = malloc_copy_prefix(1, &(ptr->info_ptr.user_specified),tmp,28);
			fixIPPacketInICMPPacket(ptr);
			break;
		default:
			//fprintf(stderr,"Error: %s\n","parseInternetControlMessagingProtocolFormat - bad type/code");
			printf("Error: %s\n","parseInternetControlMessagingProtocolFormat - bad type/code");
			exit(-1);
			break;
	}
	
	ptr->freePacket = &freeICMPPacket;
}

void printInternetControlMessagingProtocolFormat(protocol_ptr pptr, char hex_flag){
	int n = 0;
	char buffer[2];
	int hardware_length = 0;
	int protocol_length = 0;
	int type = 0;
	int code = 0;
	int new_code = 0;
	
	InternetControlMessagingProtocolFormat_ptr ptr;
	confirmProtocol(pptr, "printInternetControlMessagingProtocolFormat", ICMP);
	ptr = (InternetControlMessagingProtocolFormat_ptr) pptr->protocol_format;
	
	if(ptr == 0 ){
		//fprintf(stderr,"Error:\t%s\n","Null Pointer Exception - printAddressResolutionProtocolFormat");
		printf("Error:\t%s\n","Null Pointer Exception - printAddressResolutionProtocolFormat");
		exit(-1);
	}
	
	//Universal
	print_string_safely_with_title(1, "code", buffer, ptr->head.info.code, 1, hex_flag);
	print_string_safely_with_title(1, "type", buffer, ptr->head.info.type, 1, hex_flag);
	print_string_safely_with_title(1, "checksum", buffer, ptr->head.info.checksum, 2, hex_flag);
	
	type = (unsigned int) ptr->head.info.type[0];
	code = (unsigned int) ptr->head.info.code[0];
	new_code = getModifiedCode(type, code);
	
	//ID and Sequence stuff
	switch(new_code){
		case 3501: //8
		case 3493: //0
		case 3506://13
		case 3507://14
		case 3498://5
		case 5993://5
		case 6991://5
			print_string_safely_with_title(1, "identification", buffer, ptr->parameter.params.identification, 2, hex_flag);
			print_string_safely_with_title(1, "sequence_number", buffer, ptr->parameter.params.sequence_number, 2, hex_flag);
			break;
		default: //Do nothing
			printf("Empty\n");
			exit(-1);
			break;
	}

	switch(new_code){
		case 3501://8
		case 3493://0
			print_string_safely_with_title(1, "user_specified", buffer, ptr->info_ptr.user_specified, 2, hex_flag);
			break;
		case 3506://13
		case 3507://14
			//ptr->info_ptr.union_ptr->time.original_timestamp
			print_string_safely_with_title(1, "original_timestamp", buffer, ptr->info_ptr.union_ptr->time.original_timestamp, 2, hex_flag);
			//ptr->info_ptr.union_ptr->time.recieve_timestamp
			print_string_safely_with_title(1, "recieve_timestamp", buffer, ptr->info_ptr.union_ptr->time.recieve_timestamp, 2, hex_flag);
			//ptr->info_ptr.union_ptr->time.transmit_timestamp
			print_string_safely_with_title(1, "transmit_timestamp", buffer, ptr->info_ptr.union_ptr->time.transmit_timestamp, 2, hex_flag);
			break;
		case 3995://3
		case 5991://3
		case 6989://3
		case 3504://11
		case 6997://11
		case 3498://5
		case 5993://5
		case 6991://5
			printIPPacketFormatAsIP(ptr->info_ptr.ip_ptr, hex_flag, 1);
			break;
		default:
			//fprintf(stderr,"Error: %s\n","parseInternetControlMessagingProtocolFormat - bad type/code");
			printf("Error: %s\n","parseInternetControlMessagingProtocolFormat - bad type/code");
			exit(-1);
			break;
	}
}

void freePacketICMP(protocol_ptr pptr){
	InternetControlMessagingProtocolFormat_ptr ptr;
	if(pptr != 0){
		confirmProtocol(pptr, "printInternetControlMessagingProtocolFormat", ICMP);
		ptr = (InternetControlMessagingProtocolFormat_ptr) pptr->protocol_format;
		if(ptr != 0){
			ptr->freePacket(ptr);
		}
		free(pptr);
	}
}

protocol_ptr initializeInternetControlMessagingProtocolPacketCommands(){
	protocol_ptr ptr = mallocProtocolTypeStruct(sizeof(struct InternetControlMessagingProtocolFormat));

	ptr->type		= ICMP;
	ptr->print		= &printInternetControlMessagingProtocolFormat;
	ptr->parse		= &parseInternetControlMessagingProtocolFormat;
	ptr->freePacket	= &freePacketICMP;

	return ptr;
}
