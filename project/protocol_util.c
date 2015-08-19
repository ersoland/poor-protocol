#include "protocol_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


protocol_ptr mallocProtocolTypeStruct(int protocol_size){
	protocol_ptr ptr = (protocol_ptr) malloc(sizeof(struct protocol_util)+protocol_size);
	ptr->protocol_format = ((void*)ptr) + sizeof(struct protocol_util);
	return ptr;
}

void confirmProtocol(protocol_ptr pptr, char * method_str, enum protocol type){
	const char null_error_str[] = "This protocol util struct is null.";
	const char type_error_str[] = "This protocol util struct has the incorrect type";
	const char func_error_str[] = "This protocol util struct null function pointers";

	if(pptr == 0){
		//fprintf(stderr, "Error: %s; parent method: %s",null_error_str,method_str);
		printf( "Error: %s; parent method: %s",null_error_str,method_str);
		exit(-1);
	} 

	if(pptr->protocol_format == 0){
		//fprintf(stderr, "Error: %s; parent method: %s",null_error_str,method_str);
		printf("Error: %s; parent method: %s",null_error_str,method_str);
		exit(-1);
	} 

	/*if(&print == 0 || &parse == 0 || &fixPacket == 0 || &freePacket == 0 || &checkType == 0){
		fprintf(stderr, "Error: %s; parent method: %s",func_error_str,method_str);
		exit(-1);
	}*/

	if(pptr->type - type){
		//fprintf(stderr, "Error: %s; parent method: %s",type_error_str,method_str);
		printf( "Error: %s; parent method: %s",type_error_str,method_str);
		exit(-1);
	} 
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////

//Return pointer to string after prefix
//Ex:  str = abcde, end = 2, return de
char * copy_prefix_safely(char ignore_nulls_flag, char * buffer, char * str, int end){
	int free_buffer_flag = 0;
	int n = 0;
	
	if(buffer == 0 ){
		//fprintf(stderr,"Error:\t%s\n","Null Pointer Exception - copy_prefix_safely");
		printf("Error:\t%s\n","Null Pointer Exception - copy_prefix_safely");
		exit(-1);
	}
	if(str == 0 ){
		//fprintf(stderr,"Error:\t%s\n","Null Pointer Exception - copy_prefix_safely");
		printf("Error:\t%s\n","Null Pointer Exception - copy_prefix_safely");
		exit(-1);
	}
	if(end < 0 ){
		//fprintf(stderr,"Error:\t%s\n","Negative Length Exception - copy_prefix_safely");
		printf("Error:\t%s\n","Negative Length Exception - copy_prefix_safely");
		exit(-1);
	}
	
	for(n = 0; n < end && (str[n] || ignore_nulls_flag); n++){
		buffer[n] = str[n];
	}
	
	buffer[n] = '\0';
	
	if(str[n]){
		return str+n;
	}else {
		return str+n+1;
	}
}

//Return pointer to string after prefix
//Ex:  str = abcde, end = 2, return de
char * malloc_copy_prefix(char ignore_nulls_flag, char ** dst, char * src, int end){
	int free_buffer_flag = 0;
	int n = 0;
	char * array = malloc(sizeof(char)*8);
	int size = 10;
	
	if(dst == 0 ){
		//fprintf(stderr,"Error:\t%s\n","Null Pointer Exception - copy_prefix_safely");
		printf("Error:\t%s\n","Null Pointer Exception - copy_prefix_safely");
		exit(-1);
	}
	if(src == 0 ){
		//fprintf(stderr,"Error:\t%s\n","Null Pointer Exception - copy_prefix_safely");
		printf("Error:\t%s\n","Null Pointer Exception - copy_prefix_safely");
		exit(-1);
	}
	if(end < 0 ){
		//fprintf(stderr,"Error:\t%s\n","Negative Length Exception - copy_prefix_safely");
		printf("Error:\t%s\n","Negative Length Exception - copy_prefix_safely");
		exit(-1);
	}
	
	for(n = 0; n < end && (src[n] || ignore_nulls_flag); n++){
		if(n > size-1){
			array = realloc(array,size*2);
		}
		array[n] = src[n];
	}
	
	array[n] = '\0';
	
	dst[0] = array;
	
	if(src[n]){
		return src+n;
	}else {
		return src+n+1;
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////

void print_string(char ignore_nulls_flag, char * str, int len, char hex_flag){
	int n = 0;
	unsigned char c = 0;
	if(str == 0 ){
		//fprintf(stderr,"Error:\t%s\n","Null Pointer Exception - print_string");
		printf("Error:\t%s\n","Null Pointer Exception - print_string");
		exit(-1);
	}
	
	if((len < 0 && !ignore_nulls_flag)){
		//fprintf(stderr,"Error:\t%s\n","Invalid Argument Exception - must end with length or null value");
		printf("Error:\t%s\n","Invalid Argument Exception - must end with length or null value");
		exit(-1);
	}
	
	if(hex_flag){
		for(n = 0; (n < len || len < 0) && (*str || ignore_nulls_flag);n++){
			c = (unsigned char)(*str++);
			if(c == 0) {
				printf("--");
			}else {
				printf("%02X",c);
			}
			if((n+1 < len || len < 0) && (*str || ignore_nulls_flag))printf(":");
		}
	} else {
		for(n = 0; (n < len || len < 0) && (*str || ignore_nulls_flag);n++){
			c = (unsigned char)(*str++);
			if(c == 0) {
				printf("-");
			}else {
				printf("%c",c);
			}
		}
	}
}

void print_string_with_title(char ignore_nulls_flag, char * title, char * str, int len, char hex_flag){
	if(title == 0 ){
		//fprintf(stderr,"Error:\t%s\n","Null Pointer Exception - print_string_safely_with_title");
		printf("Error:\t%s\n","Null Pointer Exception - print_string_safely_with_title");
		exit(-1);
	}
	printf("%s = [",title);
	print_string(ignore_nulls_flag, str, len, hex_flag);
	printf("]\n");
}


void print_string_safely(char ignore_nulls_flag, char * buffer, char * str, int len, char hex_flag){
	int free_buffer_flag = 0;
	int tmp_len = 0;
	int n = 0;
	char c = 0;
	char * tmp;
	if(str == 0 ){
		//fprintf(stderr,"Error:\t%s\n","Null Pointer Exception - print_string_safely");
		printf("Error:\t%s\n","Null Pointer Exception - print_string_safely");
		exit(-1);
	}
	if(len < 0 ){
		//fprintf(stderr,"Error:\t%s\n","Negative Length Exception - print_string_safely");
		printf("Error:\t%s\n","Negative Length Exception - print_string_safely");
		exit(-1);
	}
	
	if(buffer == 0){
		buffer = malloc(sizeof(char) * (len+2));
		free_buffer_flag = 1;
	}
	
	tmp = copy_prefix_safely(ignore_nulls_flag, buffer, str,len);
	tmp_len = (int)(tmp - str);
	buffer[tmp_len] = '\0';
	
	print_string(ignore_nulls_flag, buffer, len, hex_flag);
	
	if(free_buffer_flag){
		free(buffer);
	}
}

void print_string_safely_with_title(char ignore_nulls_flag, char * title,char * buffer, char * str, int len, char hex_flag){
	if(title == 0 ){
		//fprintf(stderr,"Error:\t%s\n","Null Pointer Exception - print_string_safely_with_title");
		printf("Error:\t%s\n","Null Pointer Exception - print_string_safely_with_title");
		exit(-1);
	}
	printf("%s = [",title);
	print_string_safely(ignore_nulls_flag, buffer, str, len, hex_flag);
	printf("]\n");
}
