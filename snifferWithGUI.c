/*With GUI*/ 
struct sockaddr_in source,dest;
int tcp=0,udp=0,http = 0, dns = 0,others=0,total=0,othera = 0,abc=1,i,j,row=2;
FILE *logfile;

char Sr[5], SrcAddr[50], DestAddr[50],Prot[50];
int filterflag1 = 0, filterflag2 = 0;
char *srcip;

GtkWidget *sourceIP;
GtkWidget *destIP;
GtkWidget *protocol;
GtkWidget *srcIpbtn;
GtkWidget *destIpbtn;
GtkWidget *Protbtn;
GtkWidget *entry;

int createSocket();
void processDataLinkLayer(unsigned char* , int);
void processNetworkLayer(unsigned char*, int);
void processTransportLayer(unsigned char* Buffer, int data_size,unsigned int protocol,unsigned int iphdrlen);
void processTCP(unsigned char* Buffer, int data_size,unsigned int iphdrlen);
void processUDP(unsigned char *Buffer , int data_size, unsigned int iphdrlen);
void processApplicationLayer(unsigned char*, int, int,int,int);
void PrintData(unsigned char* , int);
void f1();
void f2();
  

void f1()
{
  
  printf("F1: Filter by source IP");
  filterflag1 = 1;
  return;
}
void f2()
{
  printf("F2: Filter by Destination IP");

  filterflag2 = 1;
  return;
}

int main(int argc, char *argv[])
{

  logfile=fopen("log.txt","w");
  if(logfile==NULL) 
    printf("Unable to create log.txt file.");
  printf("Starting...\n");

  GtkWidget *window;
  GtkWidget *fixed;
  GtkWidget *btn1;
  GtkWidget *btn2;
  GtkWidget *btn3;
  GtkWidget *filterIP;
  GtkWidget *filterSeg;
  GtkWidget *label2;
  GtkWidget *label3;
  GtkWidget *label4;
  GtkWidget *maingrid;


  gtk_init(&argc, &argv);

  window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  gtk_window_set_title(GTK_WINDOW(window), "Trackify");
  gtk_window_set_default_size(GTK_WINDOW(window), 1500, 1500);
  gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER);
  gtk_container_set_border_width(GTK_CONTAINER(window), 5);

  fixed = gtk_fixed_new();
  gtk_container_add(GTK_CONTAINER(window), fixed);

  btn3 = gtk_button_new_with_label("Filter Packets by Source IP");
  gtk_fixed_put(GTK_FIXED(fixed), btn3, 500, 15);
  gtk_widget_set_size_request(btn3, 80, 30);
  g_signal_connect(G_OBJECT(btn3), "clicked",G_CALLBACK(f1), NULL);

  entry = gtk_entry_new();
  gtk_fixed_put(GTK_FIXED(fixed), entry, 350, 15);
  gtk_widget_set_size_request(entry, 80, 30);
  int y = gtk_entry_get_text_length (entry);
  if(y!=0)
    srcip = gtk_entry_get_text (entry);


  btn1 = gtk_button_new_with_label("Stop Sniffing");
  gtk_fixed_put(GTK_FIXED(fixed), btn1, 150, 15);
  gtk_widget_set_size_request(btn1, 80, 30);

  btn2 = gtk_button_new_with_label("Start Sniffing");
  gtk_fixed_put(GTK_FIXED(fixed), btn2, 15, 15);
  gtk_widget_set_size_request(btn2, 80, 30);
  g_signal_connect(G_OBJECT(btn2), "clicked", 
  G_CALLBACK(createSocket), NULL);

 

  //filterIP = gtk_check_button_new_with_label("Filter by Source IP Address");
  //gtk_fixed_put(GTK_FIXED(fixed),filterIP, 650, 15);
  //gtk_widget_set_size_request(filterIP, 80, 30);
    

  filterSeg = gtk_button_new_with_label("Filter Fragmented Packets");
  gtk_fixed_put(GTK_FIXED(fixed), filterSeg , 900, 15);  
  gtk_widget_set_size_request(filterSeg, 80, 30);
  g_signal_connect(G_OBJECT(filterSeg), "clicked", G_CALLBACK(f2), NULL);

  maingrid= gtk_grid_new();
  gtk_fixed_put(GTK_FIXED(fixed),maingrid, 200, 80); 
  gtk_widget_set_size_request(maingrid, 500, 1200);
  GtkWidget *label = gtk_button_new_with_label("DETAILS OF CAPTURED PACKETS");
  gtk_grid_attach(maingrid, label, 1,1,5,1);
  gtk_widget_show(maingrid);
  
  sourceIP= gtk_grid_new();
  gtk_grid_attach(maingrid, sourceIP, 1,2,1,1);
  label2 = gtk_button_new_with_label("SOURCE IP");
  gtk_grid_attach(sourceIP, label2, 1,1,1,1);

  destIP = gtk_grid_new();
  gtk_grid_attach(maingrid, destIP, 2,2,1,1);
  label3 = gtk_button_new_with_label("DESTINATION IP");
  gtk_grid_attach(destIP, label3, 1,1,1,1);
 
  protocol = gtk_grid_new();
  gtk_grid_attach(maingrid, protocol, 3,2,1,1);
  label4 = gtk_button_new_with_label("PROTOCOL");
  gtk_grid_attach(protocol, label4, 1,1,1,1);
  
  gtk_widget_show_all(window);
  g_signal_connect(G_OBJECT(window), "destroy",G_CALLBACK(gtk_main_quit), NULL);
  gtk_main();

  /*int val = createSocket();
  if(val==1)
      printf("Exiting...\n");*/

  return 0;
}


int createSocket()
{
    int saddr_size , data_size;
    struct sockaddr saddr;
    int flag2;
    unsigned char *Buffer = (unsigned char *) malloc(65536); //Its Big!
    int sock_raw = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;
    //setsockopt(sock_raw , SOL_SOCKET , SO_BINDTODEVICE , "eth0" , strlen("eth0")+ 1 );
     
    if(sock_raw < 0)
    {
        //Print the error with proper message
        perror("Socket Error");
        return 0;
    }
    for(;total<250;)
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
	      //printf("TCP:%d UDP:%d OtherT:%d HTTP:%d DNS:%d OtherA:%d Total:%d\r", tcp , udp , others , http , dns , othera, total);
        // GtkWidget *srnobtn = gtk_button_new_with_label(Sr);
        // gtk_grid_attach(srno, srnobtn, 1,row,1,1);
        
        srcIpbtn = gtk_button_new_with_label(SrcAddr);
        gtk_grid_attach(sourceIP, srcIpbtn, 1,row,1,1);
        gtk_widget_show(sourceIP);
        gtk_widget_show(srcIpbtn);

        destIpbtn = gtk_button_new_with_label(DestAddr);
        gtk_grid_attach(destIP, destIpbtn, 1,row,1,1);
        gtk_widget_show(destIpbtn);

        Protbtn = gtk_button_new_with_label(Prot);
        gtk_grid_attach(protocol, Protbtn, 1,row,1,1);
        gtk_widget_show(Protbtn);

        row++;
    }
    close(sock_raw);   
    return 1;
}


void processDataLinkLayer(unsigned char* Buffer, int data_size)
{
  strcpy(Prot,"Ethernet");
  struct ethhdr *eth = (struct ethhdr *)Buffer;
  total++;
  // char srno[5];
  // strcpy(Sr,sprintf(srno,"%d",total));
  fprintf(logfile , "\n");
  fprintf(logfile , "Ethernet Header\n");
  fprintf(logfile , "   |)-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
  fprintf(logfile , "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
  fprintf(logfile , "   |-Protocol            : %u \n",(unsigned short)eth->h_proto);

	processNetworkLayer(Buffer,data_size);
  return;
}

void processNetworkLayer(unsigned char* Buffer, int data_size)
{
    strcpy(Prot,"IP");
    unsigned short iphdrlen;
         
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );  
    iphdrlen =iph->ihl*4;
     
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr= iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
     
    fprintf(logfile , "\n");
    fprintf(logfile , "IP Header\n");
    fprintf(logfile , "   |-IP Version        : %d\n",(unsigned int)iph->version);
    fprintf(logfile , "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    fprintf(logfile , "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    fprintf(logfile , "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    fprintf(logfile , "   |-Identification    : %d\n",ntohs(iph->id));
    //fprintf(logfile , "   |-Reserved ZERO Field   : %d\n",(unsigned int)iph->ip_reserved_zero);
    //fprintf(logfile , "   |-Dont Fragment Field   : %d\n",(unsigned int)iph->ip_dont_fragment);
    //fprintf(logfile , "   |-More Fragment Field   : %d\n",(unsigned int)iph->ip_more_fragment);
    fprintf(logfile , "   |-TTL      : %d\n",(unsigned int)iph->ttl);
    fprintf(logfile , "   |-Protocol : %d\n",(unsigned int)iph->protocol);
    fprintf(logfile , "   |-Checksum : %d\n",ntohs(iph->check));
    fprintf(logfile , "   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));

    //int s1=sizeof(inet_ntoa(source.sin_addr));
    strcpy(SrcAddr,inet_ntoa(source.sin_addr));
    fprintf(logfile , "   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
    strcpy(DestAddr,inet_ntoa(dest.sin_addr));

    /*if(fragflag1)
    {
      if(strcmp(inet_ntoa(source.sin_addr),srcip)==0)
        return;
    }*/


	  unsigned int protocol = (unsigned int)iph->protocol;
	  processTransportLayer(Buffer, data_size, protocol,iphdrlen);
    return;
}
 

void processTransportLayer(unsigned char* Buffer, int data_size,unsigned int protocol,unsigned int iphdrlen)
{
	switch(protocol)
	{
		case 6: tcp++;
      strcpy(Prot,"TCP");
			processTCP(Buffer,data_size,iphdrlen);
			break;
		case 17: udp++;
      strcpy(Prot,"UDP");
			processUDP(Buffer,data_size,iphdrlen);
			break;
		default: others++;
			break;
	}
  return;
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
         
    //fprintf(logfile , "IP Header\n");
    //PrintData(Buffer,iphdrlen);   
         
    //fprintf(logfile , "TCP Header\n");
    //PrintData(Buffer+iphdrlen,tcph->doff*4); 
         
    //fprintf(logfile , "Data Payload\n");    
    //PrintData(Buffer + header_size , data_size - header_size ); 
                         
    fprintf(logfile , "\n###########################################################");
	  int destport = ntohs(tcph->dest);
	  int tcpudp = 1;
	  processApplicationLayer(Buffer, data_size, tcpudp,destport,header_size);
    return;
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
    return;
}

void processApplicationLayer(unsigned char* Buffer, int data_size, int tcpudp, int destport,int header_size)
{
	switch(tcpudp)
	{
	case 0: 
		switch(destport)
		{
		case 53: dns++;
                strcpy(Prot,"DNS(UDP)");
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
    strcpy(Prot,"DNS(TCP)");
		fprintf(logfile , "\n\n***********************DNS Payload************************\n");
                PrintData(Buffer + header_size , data_size - header_size);
		break;
		case 80: http++;
    strcpy(Prot,"HTTP");
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

  return;
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

    return;
}


