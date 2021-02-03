#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>


/*
 * PCAP file reader and parser.
 * compile with: gcc pcap-reader.c -o pcap-reader -lpcap
 *
 */
void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

int main(int argc, char** argv)
{
    pcap_t* descr;
    char errbuf[PCAP_ERRBUF_SIZE];
    char filename[128];

    if (argc < 2) {
        printf("usage: pcap-reader capture-filename\n");
        return (-1);
    }

    strncpy(filename, argv[1], 127);
    filename[127] = '\0';       // guarantees null terminated

    // open capture file for offline processing
    descr = pcap_open_offline(filename, errbuf);
    if (descr == NULL) {
        printf("pcap_open_live(%s) failed: %s\n", filename, errbuf);
        return -2;
    }

    // start packet processing loop, just like live capture
    if (pcap_loop(descr, 0, packetHandler, NULL) < 0) {
        printf("pcap_loop() failed: %s", pcap_geterr(descr));
        return -3;
    }

    printf("capture finished\n");

    return 0;
}

struct rtp_hdr_t {

   unsigned int version:2;   /* protocol version */
   unsigned int p:1;         /* padding flag */
   unsigned int x:1;         /* header extension flag */
   unsigned int cc:4;        /* CSRC count */
   unsigned int m:1;         /* marker bit */
   unsigned int pt:7;        /* payload type */

       u_int16_t seq;              /* sequence number */
       u_int32_t ts;               /* timestamp */
       u_int32_t ssrc;             /* synchronization source */
       u_int32_t csrc[1];          /* optional CSRC list */
   };

void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    const struct ether_header* ethhdr;
    const struct ip* iphdr;
    const struct tcphdr* tcphdr;
    const struct udphdr* udphdr;
    char sourceIp[INET_ADDRSTRLEN];
    char destIp[INET_ADDRSTRLEN];
    u_int sourcePort, destPort;
    u_char* data;
    int dataLength = 0;
    int dataStrLen = 0;
    char dataStr[1600];

    /* RTP HEADER DATA */
    const struct rtp_hdr_t* rtphdr;
    u_int16_t sequence_number;
    u_int32_t time_stamp;
    u_int marker_bit;

    ethhdr = (struct ether_header*)packet;

    if (ntohs(ethhdr->ether_type) == ETHERTYPE_IP) {
        iphdr = (struct ip*)(packet + sizeof(struct ether_header));
        inet_ntop(AF_INET, &(iphdr->ip_src), sourceIp, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(iphdr->ip_dst), destIp, INET_ADDRSTRLEN);

        if (iphdr->ip_p == IPPROTO_TCP) {
            	tcphdr = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            	sourcePort = ntohs(tcphdr->source);
            	destPort = ntohs(tcphdr->dest);
            	data = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
            	dataLength = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
        }
        else if (iphdr->ip_p == IPPROTO_UDP) {
            	udphdr = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            	sourcePort = ntohs(udphdr->source);
            	destPort = ntohs(udphdr->dest);
            	data = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
            	dataLength = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));

        }
	
	/* RTP HEADER DATA */
	//create pointer to rtp struct so we can access it
	rtphdr = (struct rtp_hdr_t*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
        marker_bit = ntohs(rtphdr->m);
        sequence_number = ntohs(rtphdr->seq);
        time_stamp = ntohl(rtphdr->ts);

        // print the results
        printf("%s:%d -> %s:%d\n", sourceIp, sourcePort, destIp, destPort);
	//print our RTP data
	printf("RTP DATA\nMarker bit: %d\nSequence Number: %d\nTime Stamp: %d \n", marker_bit, sequence_number, time_stamp);
#if 0
        /*
         * convert non-printable characters, other than carriage return, line feed,
         * or tab into periods when displayed.
         */
        for (int i = 0; i < dataLength; i++) {
            if ((data[i] >= 32 && data[i] <= 126) || data[i] == 10 || data[i] == 11 || data[i] == 13) {
                dataStr[dataStrLen] = (char)data[i];
            }
            else {
                dataStr[dataStrLen] = '.';
            }
            dataStrLen++;
        }
        if (dataLength > 0) {
            printf("%s\n", dataStr);
        }
#endif
    }
}