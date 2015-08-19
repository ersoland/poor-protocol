#ifndef WIRELESS_H
#define WIRELESS_H

#include "protocol_util.h"

void parseWirelessFrameFormat(protocol_ptr pptr, char * array);

void printWirelessFrameFormat(protocol_ptr pptr, char hex_flag);

void freePacketWLF(protocol_ptr pptr);

protocol_ptr initializeWirelessEthernetPacketCommands();

#endif
