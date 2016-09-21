#include<pcap/pcap.h>
#include<stdint.h>
#include<stdio.h>
#include<net/ethernet.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<arpa/inet.h>
#define SIZE_ETHERNET 14

typedef struct mac_addr{

	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6; 
}mac;

int main(int argc, char *argv[])
{
		pcap_t *handle;			
		char *dev;		
		char errbuf[PCAP_ERRBUF_SIZE];	
		struct bpf_program fp;		
		bpf_u_int32 net;
		struct pcap_pkthdr * header;
		const u_char * data;
		int result;
		const struct ether_header *ethernet; 
		const struct ip *internet_proto; 
		const struct tcphdr *tcp; 
		const char *payload; 
		mac * src_mac;
		mac * des_mac;
		int total_header_len;
		int data_len;
		int i;
		

		dev = pcap_lookupdev(errbuf);

		if (dev == NULL) {

			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);

			return(2);

		}


		

		handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

		if (handle == NULL) {

			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);

			return(2);

		}



		while(1)
		{
			result = pcap_next_ex(handle, &header,&data);

			if(result != 0)

			{

				ethernet = (ether_header *) data;
				src_mac=(mac *)ethernet->ether_shost;
				des_mac=(mac *)ethernet->ether_dhost;

				printf("Source Mac address: %02x:%02x:%02x:%02x:%02x:%02x \n", src_mac->byte1, src_mac->byte2, src_mac->byte3,src_mac->byte4,src_mac->byte5, src_mac->byte6);
				printf("Destination Mac address: %02x:%02x:%02x:%02x:%02x:%02x \n", des_mac->byte1, des_mac->byte2, des_mac->byte3,des_mac->byte4,des_mac->byte5, des_mac->byte6);

				if(ntohs(ethernet-> ether_type) != 0x0800)
					printf("This packet does not use IP\n ");
				else
				{
					internet_proto=(const struct ip*)(data+14);
					printf("Source IP: %s \n",inet_ntoa(internet_proto->ip_src));
					printf("Destination IP: %s \n", inet_ntoa(internet_proto->ip_dst));

					if(internet_proto->ip_p != IPPROTO_TCP)
						printf("This packet use IP but does not use TCP\n");
					else
					{
						tcp=(const struct tcphdr*)(data+14+(internet_proto->ip_hl*4));
						printf("Source Port :%d\n", ntohs(tcp->th_sport));
						printf("Destination Port: %d\n", ntohs(tcp->th_dport));

						total_header_len=14+(4*internet_proto->ip_hl)+(4*tcp->th_off);
						data_len= header->caplen - total_header_len;
						printf("hexa decimal value of Payload : ");
						for(i=total_header_len;i< header->caplen;i++ )
							printf("%02X ", data[i]);				
					}
			

				}

		
			}		

		

	
	}
	pcap_close(handle);
	return (0);
}
