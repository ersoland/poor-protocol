#ifndef PROTOCOL_INTERFACE_H
#define PROTOCOL_INTERFACE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum protocol{
	WIRED,
	WIRELESS,
	IP,
	ARP,
	ICMP
};

typedef struct protocol_util * protocol_ptr;
struct protocol_util{
	enum protocol type;
	void * protocol_format;
	void (*print)(protocol_ptr, char);
	void (*parse)(protocol_ptr,char * str);
	void (*freePacket)(protocol_ptr);
};

//will stop program if fails
void confirmProtocol(protocol_ptr pptr,char * method_str, enum protocol type);
protocol_ptr mallocProtocolTypeStruct(int protocol_size);

char * copy_prefix_safely(char ignore_nulls_flag, char * buffer, char * str, int end);
//Return pointer to string after prefix
//Ex:  str = abcde, end = 2, return de
char * malloc_copy_prefix(char ignore_nulls_flag, char ** dst, char * src, int end);
void print_string(char ignore_nulls_flag, char * str, int len, char hex_flag);
void print_string_with_title(char ignore_nulls_flag, char * title, char * str, int len, char hex_flag);

void print_string_safely(char ignore_nulls_flag, char * buffer, char * str, int len, char hex_flag);
void print_string_safely_with_title(char ignore_nulls_flag, char * title,char * buffer, char * str, int len, char hex_flag);

#endif

