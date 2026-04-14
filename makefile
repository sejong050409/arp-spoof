all: arp-spoof

arp-spoof: main.cpp ethernet.h arp.h packet.h
	g++ -o arp-spoof  main.cpp -lpcap

clean:
	rm -f arp-spoof
