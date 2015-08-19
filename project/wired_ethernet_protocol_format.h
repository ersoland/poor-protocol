#ifndef WIRED_H
#define WIRED_H

#include "protocol_util.h"

void parseWiredFrameFormat(protocol_ptr pptr, char * array);

void printWiredFrameFormat(protocol_ptr pptr, char hex_flag);

void freePacketWEP(protocol_ptr pptr);

char checkTypeWEP(protocol_ptr ptr, enum protocol type);

protocol_ptr initializeWiredEthernetPacketCommands();

#endif
