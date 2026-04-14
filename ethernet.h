#define ETHERNET_H
#include <stdint.h>

#pragma pack(push, 1)
typedef struct{
	uint8_t dst_mac[6];
	uint8_t src_mac[6];
	uint16_t ethertype;
} ethernet_header;
#pragma pack(pop)

#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP 0x0806
#define ETHERMAC_LEN 6
