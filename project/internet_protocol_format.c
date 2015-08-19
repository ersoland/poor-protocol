
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "protocol_util.h"
#include "internet_protocol_format.h"

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

void freeIPPacketFormat(IPPacketFormat_ptr ptr){
	
	if(ptr->options){
		if(ptr->data != (char*) (((void*)ptr)+ sizeof(IPPacketHeaderUnion))){
			free(ptr->options);
		}
	}
	
	if(ptr->data){
		if(ptr->data != (char*) (((void*)ptr)+ sizeof(IPPacketHeaderUnion))){
			free(ptr->data);
		} else if(ptr->data != (char*) (((void*)ptr)+ sizeof(IPPacketHeaderUnion) + 4)){
			free(ptr->data);
		}
	}
}

int parseLengthFromAwkwardlyDesignedStructure(IPPacketFormat_ptr ptr){

	int length = 0;
	length = (unsigned int)ptr->header.info.length[1];
	length = length | (((unsigned int)ptr->header.info.length[0]) << 8);

	return length;
}

void parseIPPacketFormat(protocol_ptr pptr, char * array){
	int n = 0;
	int length = 0;
	char *tmp;
	IPPacketFormat_ptr ptr;

	confirmProtocol(pptr, "parseIPPacketFormat", IP);
	ptr = (IPPacketFormat_ptr) pptr->protocol_format;

	if(array == 0 ){
		//fprintf(stderr,"Error:\t%s\n","Null Pointer Exception - parseIPPacketFormat");
		printf("Error:\t%s\n","Null Pointer Exception - parseIPPacketFormat");
		exit(-1);
	}
	
	tmp = array;
	tmp = copy_prefix_safely(1, ptr->header.array,tmp,20);
	
	length = ((int)(ptr->header.info.version.nibbles.header_length))*4-20;
	if(length < 0) printf("length = %d, str = %s, hlen = %d, version = %d\n",
		length,ptr->header.info.version.str,ptr->header.info.version.nibbles.header_length,
		ptr->header.info.version.nibbles.version_number );
	tmp = malloc_copy_prefix(1, &(ptr->options),tmp,length);

	//length = ((int*)(ptr->header.info.length))[0];
	
	length = parseLengthFromAwkwardlyDesignedStructure(ptr);
	//if(length < 0) 
	{
		printf("length = %d, str = %s",length,ptr->header.info.length );
	}
	tmp = malloc_copy_prefix(0, &(ptr->data),tmp,length);
	
	ptr->freePacket = &freeIPPacketFormat;
}

void printIPPacketFormatAsIP(IPPacketFormat_ptr ptr, char hex_flag, char blank_field_flag){

	char buffer[4];
	int length = 0;

	if(ptr == 0 ){
		//fprintf(stderr,"Error:\t%s\n","Null Pointer Exception - printIPPacketFormatAsIP");
		printf("Error:\t%s\n","Null Pointer Exception - printIPPacketFormatAsIP");
		exit(-1);
	}

	print_string_safely_with_title(1, "version_number and header_length", buffer,ptr-> header.info.version.str		,1,hex_flag);
	print_string_safely_with_title(1, "type_of_service"			, buffer,ptr-> header.info.type_of_service			,1,hex_flag);
	print_string_safely_with_title(1, "length"					, buffer,ptr-> header.info.length					,2,hex_flag);
	print_string_safely_with_title(1, "identifier"				, buffer,ptr-> header.info.identifier				,2,hex_flag);
	print_string_safely_with_title(1, "flags and offset"		, buffer,ptr-> header.info.flags.str				,2,hex_flag);
	print_string_safely_with_title(1, "time_to_live"			, buffer,ptr-> header.info.time_to_live				,1,hex_flag);
	print_string_safely_with_title(1, "protocol"				, buffer,ptr-> header.info.protocol					,1,hex_flag);
	print_string_safely_with_title(1, "checksum"				, buffer,ptr-> header.info.checksum					,2,hex_flag);
	print_string_safely_with_title(1, "source_IP_address"		, buffer,ptr-> header.info.source_IP_address		,4,hex_flag);
	print_string_safely_with_title(1, "destination_IP_address"	, buffer,ptr-> header.info.destination_IP_address	,4,hex_flag);
	
	if(blank_field_flag){
		print_string_with_title(1, "options/data"	, ptr->blank	, 8, hex_flag);
	}
	else{
		length = ((unsigned int)(ptr->header.info.version.nibbles.header_length))*4-20;
		print_string_with_title(1, "options"	, ptr->options	, length, hex_flag);

		length = parseLengthFromAwkwardlyDesignedStructure(ptr);
		print_string_with_title(1, "data"		, ptr->data		, length, hex_flag);
	}
}

void printIPPacketFormat(protocol_ptr pptr, char hex_flag){
	IPPacketFormat_ptr ptr;

	confirmProtocol(pptr, "printIPPacketFormat", IP);
	ptr = (IPPacketFormat_ptr) pptr->protocol_format;
	
	printIPPacketFormatAsIP(ptr, hex_flag, 0);
}

void freePacketIPF(protocol_ptr pptr){
	IPPacketFormat_ptr ptr;
	confirmProtocol(pptr, "parseIPPacketFormat", IP);
	ptr = (IPPacketFormat_ptr) pptr->protocol_format;

	if(ptr != 0) {
		ptr->freePacket(ptr);
		free(pptr);
	}
}

protocol_ptr initializeInternetProtocolPacketCommands(){
	protocol_ptr ptr = mallocProtocolTypeStruct(sizeof(struct IPPacketFormat));

	ptr->type		= IP;
	ptr->print		= &printIPPacketFormat;
	ptr->parse		= &parseIPPacketFormat;
	ptr->freePacket	= &freePacketIPF;

	return ptr;
}

