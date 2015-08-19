
#ifndef ARP_H
#define ARP_H

#include "protocol_util.h"

typedef struct InternetControlMessagingProtocolFormat * InternetControlMessagingProtocolFormat_ptr;
struct InternetControlMessagingProtocolFormat;

void parseInternetControlMessagingProtocolFormat(protocol_ptr ptr, char * array);

void printInternetControlMessagingProtocolFormat(protocol_ptr ptr, char hex_flag);

void freePacketICMP(protocol_ptr pptr);

protocol_ptr initializeInternetControlMessagingProtocolPacketCommands();

#endif
