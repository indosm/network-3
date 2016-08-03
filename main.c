// This is an example program from the website www.microhowto.info
// © 2012 Graham Shaw
// Copying and distribution of this software, with or without modification,
// is permitted in any medium without royalty.
// This software is offered as-is, without any warranty.

// Purpose: to construct an ARP request and write it to an Ethernet interface
// using libpcap.
//
// See: "Send an arbitrary Ethernet frame using libpcap"
// http://www.microhowto.info/howto/send_an_arbitrary_ethernet_frame_using_libpcap.html

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>

int main(int argc,const char* argv[]) {
    // Get interface name and target IP address from command line.
    if (argc<2) {
        fprintf(stderr,"usage: send_arp <interface> <ipv4-address>\n");
        exit(1);
    }
    char myip_tmp[20];
    char gateip_tmp[20];
    char mymac_tmp[20];
    FILE *fp;
    //finding my ip address
    fp = popen( "ip addr | grep \"inet\" | grep brd | awk '{print $2}' | awk -F/ '{print $1}'", "r");
    if(fp==NULL)
    {
        perror("popen Error!\n");
        return -1;
    }
    fgets( myip_tmp, 20, fp);
    printf("My ip : %s", myip_tmp);
    pclose(fp);
    //finding my MAC address
    fp = popen("ifconfig | grep HWaddr | awk '{print $5}'","r");
    if (fp ==NULL)
    {
        perror("popen Error!!\n");
        return -1;
    }
    fgets(mymac_tmp, 20, fp);
    printf("My Mac address : %s",mymac_tmp);
    pclose(fp);
    //finding Gateway's ip address
    fp = popen("route | grep default | awk '{print $2}'","r");
    if (fp ==NULL)
    {
        perror("popen Error!!\n");
        return -1;
    }
    fgets(gateip_tmp, 20, fp);
    printf("Gateway ip : %s",gateip_tmp);
    pclose(fp);

    const char* if_name=argv[1];
    const char* target_ip_string=argv[2];
    // Construct Ethernet header (except for source MAC address).
    // (Destination set to broadcast address, FF:FF:FF:FF:FF:FF.)
    struct ether_header header;
    header.ether_type=htons(ETH_P_ARP);
    memset(header.ether_dhost,0xff,sizeof(header.ether_dhost));

    // Construct ARP request (except for MAC and IP addresses).
    struct ether_arp req;
    req.arp_hrd=htons(ARPHRD_ETHER);
    req.arp_pro=htons(ETH_P_IP);
    req.arp_hln=ETHER_ADDR_LEN;
    req.arp_pln=sizeof(in_addr_t);
    req.arp_op=htons(ARPOP_REQUEST);
    memset(&req.arp_tha,0,sizeof(req.arp_tha));

    // Convert target IP address from string, copy into ARP request.
    struct in_addr target_ip_addr={0};
    if (!inet_aton(target_ip_string,&target_ip_addr)) {
       fprintf(stderr,"%s is not a valid IP address",target_ip_string);
       exit(1);
    }
    memcpy(&req.arp_tpa,&target_ip_addr.s_addr,sizeof(req.arp_tpa));

    // Write the interface name to an ifreq structure,
    // for obtaining the source MAC and IP addresses.
    struct ifreq ifr;
    size_t if_name_len=strlen(if_name);
    if (if_name_len<sizeof(ifr.ifr_name)) {
        memcpy(ifr.ifr_name,if_name,if_name_len);
        ifr.ifr_name[if_name_len]=0;
    } else {
        fprintf(stderr,"interface name is too long");
        exit(1);
    }

    // Open an IPv4-family socket for use when calling ioctl.
    int fd=socket(AF_INET,SOCK_DGRAM,0);
    if (fd==-1) {
        perror(0);
        exit(1);
    }

    // Obtain the source IP address, copy into ARP request
    if (ioctl(fd,SIOCGIFADDR,&ifr)==-1) {
        perror(0);
        close(fd);
        exit(1);
    }
    struct sockaddr_in* source_ip_addr = (struct sockaddr_in*)&ifr.ifr_addr;
    memcpy(&req.arp_spa,&source_ip_addr->
           sin_addr.s_addr,sizeof(req.arp_spa));

    // Obtain the source MAC address, copy into Ethernet header and ARP request.
    if (ioctl(fd,SIOCGIFHWADDR,&ifr)==-1) {
        perror(0);
        close(fd);
        exit(1);
    }
    if (ifr.ifr_hwaddr.sa_family!=ARPHRD_ETHER) {
        fprintf(stderr,"not an Ethernet interface");
        close(fd);
        exit(1);
    }
    const unsigned char* source_mac_addr=(unsigned char*)ifr.ifr_hwaddr.sa_data;
    memcpy(header.ether_shost,source_mac_addr,sizeof(header.ether_shost));
    memcpy(&req.arp_sha,source_mac_addr,sizeof(req.arp_sha));
    close(fd);

    // Combine the Ethernet header and ARP request into a contiguous block.
    unsigned char frame[sizeof(struct ether_header)+sizeof(struct ether_arp)];
    memcpy(frame,&header,sizeof(struct ether_header));
    memcpy(frame+sizeof(struct ether_header),&req,sizeof(struct ether_arp));

    // Open a PCAP packet capture descriptor for the specified interface.
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    pcap_errbuf[0]='\0';
    pcap_t* pcap=pcap_open_live(if_name,96,0,0,pcap_errbuf);
    if (pcap_errbuf[0]!='\0') {
        fprintf(stderr,"%s\n",pcap_errbuf);
    }
    if (!pcap) {
        exit(1);
    }

    // Write the Ethernet frame to the interface.
    if (pcap_inject(pcap,frame,sizeof(frame))==-1) {
        pcap_perror(pcap,0);
        pcap_close(pcap);
        exit(1);
    }
    pcap_t *handle;			/* Session handle */
    char *dev;			/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */
    struct pcap_pkthdr *header2;	/* The header that pcap gives us */
    const u_char *packet;		/* The actual packet */
    const u_char *eptr;	        /* start address of Ethernet*/
    const u_char *arp;           /* start address of IP*/
    const u_char *tcp;          /* start address of TCP*/
    int version;
    int length;
    while(1){
        /* Grab a packet */
        const int rst = pcap_next_ex(pcap, &header2, &packet);
        if(rst<0){   //can't get packet
            printf("hi1\n");
            break;
        }
        else if(rst==0)     //get no packet
            continue;
        /* Print its length */
        printf("------------------------------------------\n");
        printf("Jacked a packet with length of [%d]\n", header2->len);
        eptr = packet;
        printf("ETHERNET PACKET : \n");
        printf("\tDestination Mac\t: ");
        for(int i=0;i<=5;i++)
        {
            printf("%x%s",*(eptr+i),(i==5?"":":"));
        }
        printf("\n\tSource MAC\t: ");
        for(int i=6;i<=11;i++)
        {
            printf("%x%s",*(eptr+i),(i==11?"":":"));
        }
        printf("\n\t");
        if(ntohs(*(short*)(eptr+12))==0x0800){
            printf("-> IP packet\n");
            continue;
        }
        else if(ntohs(*(short*)(eptr+12))==0x0806){
            printf("-> ARP packet\n");
        }
        else{
            printf("-> Not IP\n");
            continue;
        }
        // ARP Packet
        arp = eptr+14;
        printf("\tTarget IP\t: ");
        for(int i=24;i<=27;i++)
        {
            printf("%d%s",*(arp+i),(i==27?"":"."));
        }
        printf("\n\tSender IP\t: ");
        for(int i=14;i<=17;i++)
        {
            printf("%d%s",*(arp+i),(i==17?"":"."));
        }
        if(strcmp(argv[2],arp+14)==0)
        {
            printf("Good!");
        }
        printf("\n");
        break;
    }
    // Close the PCAP descriptor.
    pcap_close(pcap);
    return 0;
}
