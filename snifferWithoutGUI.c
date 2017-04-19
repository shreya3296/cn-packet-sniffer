/*Without GUI*/
#include<netinet/in.h>
#include<errno.h>
#include<netdb.h>
#include<stdio.h> //For standard things
#include<stdlib.h>    //malloc
#include<string.h>   //strlen
   
 
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<netinet/if_ether.h>  //For ETH_P_ALL
#include<net/ethernet.h>  //For ether_header
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/time.h>
#include<sys/types.h>
#include<unistd.h>
 
struct sockaddr_in source,dest;
int tcp=0,udp=0,http = 0, dns = 0,others=0,total=0,othera = 0,i,j;
int fragflag1 = 0,fragflag2 = 0;
FILE *logfile;
char srcip[50];


int createSocket();
void processDataLinkLayer(unsigned char* , int);
void processNetworkLayer(unsigned char*, int);
void processTransportLayer(unsigned char* Buffer, int data_size,unsigned int protocol,unsigned int iphdrlen);
void processTCP(unsigned char* Buffer, int data_size,unsigned int iphdrlen);
void processUDP(unsigned char *Buffer , int data_size, unsigned int iphdrlen);
void processApplicationLayer(unsigned char*, int, int,int,int);
void PrintData(unsigned char* , int);
int checkFragment(int offset);

int main(int argc, char *argv[])
{
    logfile=fopen("log.txt","w");
    if(logfile==NULL) 
        printf("Unable to create log.txt file.");
    int choice;
    printf("\n Enter Choice:\n");
    printf("1. Basic Packet Capture\n");
    printf("2. Filter By Source IP\n");
    printf("3. Filter By Fragmentation\n");
    scanf("%d",&choice);
    switch(choice)
    {
        case 1: break;
        case 2: fragflag1 = 1;
                printf("Enter Source IP");
                scanf("%s",srcip);
                break;
        case 3: fragflag2 = 1;
                break;
        default:    printf("Error Input: Beginning Simple Packet Capture");
                break;
    }
    printf("Starting...\n");
    int val=createSocket();
    if(val==1)
        printf("Exiting...\n");
    return 0;
}

int createSocket()
{
    int saddr_size , data_size;
    struct sockaddr saddr;
         
    unsigned char *Buffer = (unsigned char *) malloc(65536); //Its Big!
    int sock_raw = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;
    //setsockopt(sock_raw , SOL_SOCKET , SO_BINDTODEVICE , "eth0" , strlen("eth0")+ 1 );
     
    if(sock_raw < 0)
    {
        //Print the error with proper message
        perror("Socket Error");
        return 0;
    }
    while(1)
    {
      
        saddr_size = sizeof saddr;  //******size of socket??
        //Receive a packet
        data_size = recvfrom(sock_raw , Buffer , 65536 , 0 , &saddr , (socklen_t*)&saddr_size);

        if(data_size <0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            return 0;
        }
        //Now process the packet
	
        processDataLinkLayer(Buffer , data_size);
	    printf("TCP:%d UDP:%d OtherT:%d HTTP:%d DNS:%d OtherA:%d Total:%d\r", tcp , udp , others , http , dns , othera, total);
      
     }

    close(sock_raw);
    printf("Finished");
    return 1;
}


void processDataLinkLayer(unsigned char* Buffer, int data_size)
{
    struct ethhdr *eth = (struct ethhdr *)Buffer;
    total++;
    fprintf(logfile , "\n");
    fprintf(logfile , "Ethernet Header\n");
    fprintf(logfile , "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    fprintf(logfile , "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    fprintf(logfile , "   |-Protocol            : %u \n",(unsigned short)eth->h_proto);

	processNetworkLayer(Buffer,data_size);
}

void processNetworkLayer(unsigned char* Buffer, int data_size)
{
    unsigned short iphdrlen;
         
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );  
    iphdrlen =iph->ihl*4;
     
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr= iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
     
    unsigned int protocol = (unsigned int)iph->protocol;
    if(fragflag1 && (strcmp(inet_ntoa(source.sin_addr),srcip)==0))
        return;
    unsigned int offset = ntohs(iph->frag_off);
    if(fragflag2 && checkFragment(offset))
        return;
    //printf("%d\n",offset);
 
    fprintf(logfile , "\n");
    fprintf(logfile , "IP Header\n");
    fprintf(logfile , "   |-IP Version        : %d\n",(unsigned int)iph->version);
    fprintf(logfile , "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    fprintf(logfile , "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    fprintf(logfile , "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    fprintf(logfile , "   |-Identification    : %d\n",ntohs(iph->id));
    //fprintf(logfile , "   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
    //fprintf(logfile , "   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
    //fprintf(logfile , "   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
    fprintf(logfile , "   |-TTL      : %d\n",(unsigned int)iph->ttl);
    fprintf(logfile , "   |-Protocol : %d\n",(unsigned int)iph->protocol);
    fprintf(logfile , "   |-Checksum : %d\n",ntohs(iph->check));
    fprintf(logfile , "   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
    fprintf(logfile , "   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));

	
	processTransportLayer(Buffer, data_size, protocol,iphdrlen);

}
 

void processTransportLayer(unsigned char* Buffer, int data_size,unsigned int protocol,unsigned int iphdrlen)
{
	switch(protocol)
	{
		case 6: tcp++;
			processTCP(Buffer,data_size,iphdrlen);
			break;
		case 17: udp++;
			processUDP(Buffer,data_size,iphdrlen);
			break;
		default: others++;
			break;
	}
}
			
void processTCP(unsigned char* Buffer, int data_size,unsigned int iphdrlen)
{
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr)); 
             
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
     
    fprintf(logfile , "\n\n***********************TCP Packet*************************\n");  
         
         
    fprintf(logfile , "\n");
    fprintf(logfile , "TCP Header\n");
    fprintf(logfile , "   |-Source Port      : %u\n",ntohs(tcph->source));
    fprintf(logfile , "   |-Destination Port : %u\n",ntohs(tcph->dest));
    fprintf(logfile , "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    fprintf(logfile , "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    fprintf(logfile , "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    //fprintf(logfile , "   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
    //fprintf(logfile , "   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
    fprintf(logfile , "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    fprintf(logfile , "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    fprintf(logfile , "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    fprintf(logfile , "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    fprintf(logfile , "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    fprintf(logfile , "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    fprintf(logfile , "   |-Window         : %d\n",ntohs(tcph->window));
    fprintf(logfile , "   |-Checksum       : %d\n",ntohs(tcph->check));
    fprintf(logfile , "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    fprintf(logfile , "\n");
    fprintf(logfile , "                        DATA Dump                         ");
    fprintf(logfile , "\n");
                         
    fprintf(logfile , "\n###########################################################");
	int destport = ntohs(tcph->dest);
	int tcpudp = 1;
	processApplicationLayer(Buffer, data_size, tcpudp,destport,header_size);
}

void processUDP(unsigned char *Buffer , int data_size, unsigned int iphdrlen)
{
    
     
    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
     
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;   // ******** sizeof updh??
     
    fprintf(logfile , "\n\n***********************UDP Packet*************************\n");
               
     
    fprintf(logfile , "\nUDP Header\n");
    fprintf(logfile , "   |-Source Port      : %d\n" , ntohs(udph->source));
    fprintf(logfile , "   |-Destination Port : %d\n" , ntohs(udph->dest));
    fprintf(logfile , "   |-UDP Length       : %d\n" , ntohs(udph->len));
    fprintf(logfile , "   |-UDP Checksum     : %d\n" , ntohs(udph->check));
     
    fprintf(logfile , "\n");
    //fprintf(logfile , "IP Header\n");
    //PrintData(Buffer , iphdrlen);
         
    //fprintf(logfile , "UDP Header\n");
    //PrintData(Buffer+iphdrlen , sizeof udph);
         
    //fprintf(logfile , "Data Payload\n");    
     
    //Move the pointer ahead and reduce the size of string
    //PrintData(Buffer + header_size , data_size - header_size);
     
    fprintf(logfile , "\n###########################################################");
	int destport = ntohs(udph->dest);
	int tcpudp = 0;
	processApplicationLayer(Buffer, data_size, tcpudp, destport,header_size);
}

void processApplicationLayer(unsigned char* Buffer, int data_size, int tcpudp, int destport,int header_size)
{
	switch(tcpudp)
	{
	case 0: 
		switch(destport)
		{
		case 53: dns++;
                fprintf(logfile , "\n\n***********************DNS Payload************************\n");
                PrintData(Buffer + header_size , data_size - header_size);
		break;
		default: othera++;
		break;
		}
		break;
	case 1: 
		switch(destport)
		{
		case 53: dns++;
		fprintf(logfile , "\n\n***********************DNS Payload************************\n");
                PrintData(Buffer + header_size , data_size - header_size);
		break;
		case 80: http++;
		fprintf(logfile , "\n\n***********************HTTP Payload************************\n");
                PrintData(Buffer + header_size , data_size - header_size);
		break;
		default: othera++;
		fprintf(logfile , "\n\n***********************Data Payload************************\n");
                PrintData(Buffer + header_size , data_size - header_size);
		}
		break;
	default: 
		break;
	}
}

void PrintData (unsigned char* data , int Size)
{
    int i , j;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            fprintf(logfile , "         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    fprintf(logfile , "%c",(unsigned char)data[j]); //if its a number or alphabet
                 
                else fprintf(logfile , "."); //otherwise print a dot
            }
            fprintf(logfile , "\n");
        } 
         
        if(i%16==0) fprintf(logfile , "   ");
            fprintf(logfile , " %02X",(unsigned int)data[i]);
                 
        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++) 
            {
              fprintf(logfile , "   "); //extra spaces
            }
             
            fprintf(logfile , "         ");
             
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) 
                {
                  fprintf(logfile , "%c",(unsigned char)data[j]);
                }
                else
                {
                  fprintf(logfile , ".");
                }
            }
             
            fprintf(logfile ,  "\n" );
        }
    }
}

int checkFragment(int offset)
{
    int i = 0;
    int bin[16];
    if(offset>0)
    {
        while(offset>0)
        {
            bin[i] = offset%2;
            i++;
            offset = offset/2;
        }
    }
    while(i<16)
    {
        bin[i] = 0;
        i++;
    }
    int flag = 0;
    i = 0;
    while(i < 13)
    {
        if(bin[i]==1)
        {
            flag = 1;
            break;
        }
        i++;
    }
    if(flag)
        return 1;
    return 0;
}
