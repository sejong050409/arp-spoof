#define ARP_H
#include <stdint.h>

#pragma pack(push, 1)
typedef struct{
	uint16_t hrd;
	uint16_t pro;
	uint8_t hln;
	uint8_t pln;
	uint16_t op;

	uint8_t smac[6];
	uint32_t sip;

	uint8_t tmac[6];
	uint32_t tip;
} arp_header;
#pragma pack(pop)

#define ARPTYPE_ETHER 0x0001
#define ARP_REQUEST 1
#define ARP_REPLY 2
