#ifndef ARP_H
#define ARP_H

#include "protocol_util.h"

void parseAddressResolutionProtocolFormat(protocol_ptr ptr, char * array);

void printAddressResolutionProtocolFormat(protocol_ptr ptr, char hex_flag);

void freePacketARP(protocol_ptr pptr);

protocol_ptr initializeAddressResolutionProtocolPacketCommands();

#endif

