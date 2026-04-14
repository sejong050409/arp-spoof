#define PACKET_H
#include "ethernet.h"
#include "arp.h"

#pragma pack(push, 1)
typedef struct{
	ethernet_header eth;
	arp_header arp;
} eth_arp_packet;
#pragma pack(pop)
