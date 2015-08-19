#include "protocol_util.h"

#include "wired_ethernet_protocol_format.h"
#include "wireless_ethernet_protocol_format.h"
#include "internet_protocol_format.h"
#include "address_resolution_protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(){
	char buffer[100];
	int length = 0;
	char * str = "Preamb.DAddrD.AddrS.FHappyDataParty!\0FCS.";
	char * str2 = "FrameC.DAddr1.Addr2.Addr3.SCAddr4.HappyDataParty!\0FCS.";
	char * str3;
	protocol_ptr ptr;

	//WIRED
	length = strlen(str) + 5;
	print_string_with_title(1,"Wired Protocol", str, length, 0);
	ptr = initializeWiredEthernetPacketCommands();
	ptr->parse(ptr, str);
	ptr->print(ptr,0);
	ptr->print(ptr,1);
	ptr->freePacket(ptr);

	//WIRELESS
	printf("\nWireless Protocol: %s\n",str2);
	ptr = initializeWirelessEthernetPacketCommands();
	ptr->parse(ptr, str2);
	ptr->print(ptr,0);
	ptr->print(ptr,1);
	ptr->freePacket(ptr);

	//IP
	asprintf(&str3,"ASAAIDFOTPCSSRC.DST.%s\0","HappyDataParty!");
	printf("\nInternet Protocol: %s\n",str3);
		//Header Length
	str3[0] = (char) (0x0005);
		//Payload Length
	str3[2] = (char) (0x0000);
	str3[3] = (char) (0x0010);
	ptr = initializeInternetProtocolPacketCommands();
	ptr->parse(ptr, str3);
	ptr->print(ptr,0);
	ptr->print(ptr,1);
	ptr->freePacket(ptr);
	free(str3);
	
	//ARP
	asprintf(&str3,"AABBCDEE%s%s%s%s\0","SendHW","Send","TargHW","Targ");
	printf("\nAddressResolutionProtocol Original = [%s]\n",str3);
		//Ethernet Address Length
	str3[4] = (char) (0x0006);
		//IP Address Length
	str3[5] = (char) (0x0004);
	ptr = initializeAddressResolutionProtocolPacketCommands();
	ptr->parse(ptr, str3);
	ptr->print(ptr,0);
	ptr->print(ptr,1);
	ptr->freePacket(ptr);
	free(str3);
	
	//ICMP

	asprintf(&str3,"XYCCNNNNABCDEFGHIJKL\0");
	printf("\nInternetControlMessagingProtocol Original = [%s]\n",str3);
		//Type
	str3[0] = (char) (0x000D);
		//Code
	str3[1] = (char) (0x0000);
	ptr = initializeInternetControlMessagingProtocolPacketCommands();
	ptr->parse(ptr, str3);
	ptr->print(ptr,0);
	ptr->print(ptr,1);
	ptr->freePacket(ptr);
	free(str3);
	
	return 0;
}
