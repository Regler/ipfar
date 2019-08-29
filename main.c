#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>  
#include <sys/types.h>  
#include <dirent.h>  
#include <sys/stat.h>  
#include <pwd.h>  
#include <grp.h>  
#include <unistd.h>  
#include <string.h>  
#include <getopt.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <time.h>
#include <pcap/pcap.h>
#include "list.h"
#define LINE_LEN 16
int mtu;
pcap_t *fp;
#define IP_HEAD 20
#define MAC_HEAD 14

typedef struct node
{
	struct pcap_pkthdr *hdr;
	u_char *data;
}Packet;


pcap_t *source_pcap_t=NULL;
pcap_dumper_t *des_pcap_dumper_t=NULL;
MyList *list=NULL;


u_short mergeu_char(u_char a,u_char b)
{
	u_short p = 0;
	p |= a;
	p = p<<8;
	p |= b;
	return p;
}

u_short checknum(u_char *data, int length)
{
	
	u_int sum =0;
	for(int i=0; i < length ;i += 2)
	{
		u_short p = mergeu_char(data[i],data[i+1]);
		printf("%x  \n", p);
		sum += (u_int)p;
	}
	printf("\n");
	printf("%x  sum \n  \n",sum);
	u_short  d = (u_short)sum;
	printf("%x  \n\n ", d);
	u_short  f = (u_short)(sum>>16);
	printf("%x   \n\n",f);

	u_short s =(u_short)(d + f);
	printf("%x   s  \n\n ",s);
	return  s;
}



void dispatcher_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data)
{

	int num_ip_fragment = (header->len - MAC_HEAD - IP_HEAD - 1 )/(mtu - IP_HEAD) + 1;
//	printf("num_ip_fragment = %d\n", num_ip_fragment);
	
//	checknum(pkt_data, 20);		

	const u_char *pdata =pkt_data + MAC_HEAD + IP_HEAD; 
	for(int i=1;i<=num_ip_fragment;i++)
	{
		

		Packet *packet = (Packet *)malloc(sizeof(Packet));
		if(i != num_ip_fragment)
		{
			packet->data = (u_char *) malloc (sizeof(u_char) *(MAC_HEAD + mtu) + 1);
			packet->hdr = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));

			packet->hdr->len = mtu + MAC_HEAD;
			packet->hdr->caplen =  mtu + MAC_HEAD;
			packet->hdr->ts.tv_sec = header->ts.tv_sec;
			packet->hdr->ts.tv_usec = header->ts.tv_usec;

			int j;
			int index= 0 ;

			for (j = 0; j < MAC_HEAD + IP_HEAD; j++)
				packet->data[index++] = pkt_data[j];


			u_char *flength = packet->data + 14 + 2;
			u_short packet_length = (u_short) mtu;
			flength[1] = (u_char)(packet_length);
			flength[0] = (u_short)(packet_length>>8);

			u_char *foffset= packet->data + 14 + 6;
			u_short offset = (i-1)*(mtu-IP_HEAD)/8;
			foffset[1] = (u_char)offset;
			foffset[0] = (u_char)(offset>>8);
			foffset[0]|= (0x20);
			
			u_char *check = packet->data + 14 + 10;
			check[0] = 0x00;
			check[1] = 0x00;
			u_short finalchecknum = checknum(packet->data + 14, 20);
			printf("%x   finanl\n",finalchecknum);

			check[1]= ~((u_short)finalchecknum);
			printf("%x   chek1\n",check[1]);

			check[0] = ~((u_short)(finalchecknum>>8));
				printf("%x   chek0\n",check[0]);

			




		

			for (j = (i-1)*(mtu-IP_HEAD); j <i*(mtu - IP_HEAD); j++ )
				packet->data[index++] = pdata[j];
			packet->data[index]='\0';

			myListInsertDataAtLast(list, packet); 
		}

		else 
		{
			packet->data = (u_char *)malloc(header->len - (mtu - IP_HEAD)*(num_ip_fragment -1) + 1);
			packet->hdr = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));

			packet->hdr->len = header->len - (mtu - IP_HEAD)*(num_ip_fragment - 1 );

			packet->hdr->caplen =  packet->hdr->len;
			packet->hdr->ts.tv_sec = header->ts.tv_sec;
			packet->hdr->ts.tv_usec = header->ts.tv_usec;

			int j;
			int index= 0 ;

			for (j = 0; j < MAC_HEAD + IP_HEAD; j++)
				packet->data[index++] = pkt_data[j];


			u_char *flength = packet->data + 14 + 2;
			u_short packet_length = (u_short)(packet->hdr->len - MAC_HEAD);
			flength[1] = (u_char)(packet_length);
			flength[0] = (u_short)(packet_length>>8);

			u_char *foffset= packet->data + 14 + 6;
			u_short offset = (i-1)*(mtu-IP_HEAD)/8;
			foffset[1] = (u_char)offset;
			foffset[0] = (u_char)(offset>>8);

			
			u_char *check = packet->data + 14 + 10;
			check[0] = 0x00;
			check[1] = 0x00;
			u_short finalchecknum = checknum(packet->data + 14, 20);
			printf("%x   finanl\n",finalchecknum);

			check[1]= ~((u_short)finalchecknum);
			printf("%x   chek1\n",check[1]);

			check[0] = ~((u_short)(finalchecknum>>8));
				printf("%x   chek0\n",check[0]);



			for (j = (num_ip_fragment - 1)*(mtu-IP_HEAD); j < header->len - MAC_HEAD - IP_HEAD; j++ )
				packet->data[index++] = pdata[j];

			packet->data[index]='\0';

			myListInsertDataAtLast(list, packet); 

		}
	}


}

void print_pcap(char *file)
{

	char errbuf[PCAP_ERRBUF_SIZE];
	//打开pcap文件
	if ((fp = pcap_open_offline(file,	   // name of the device
					errbuf					                    // error buffer
					)) == NULL)
	{
		fprintf(stderr,"\nUnable to open the file %s.\n", file);
		return ;
	}
	pcap_loop(fp, 0, dispatcher_handler, NULL);
	pcap_close(fp);

}






int exit_main()
{
	printf("exit_main() is called.\n");
	if( NULL!=source_pcap_t )
	{
		pcap_close(source_pcap_t);
	}
	if( NULL!=des_pcap_dumper_t )
	{
		pcap_dump_close(des_pcap_dumper_t);
	}
	exit(0);
}

void filter_pcap(char *file)
{
	char errbuf[PCAP_ERRBUF_SIZE]={0};
	if( NULL==(source_pcap_t=pcap_open_offline(file, errbuf)) )
	{
		printf("pcap_open_offline() return NULL.\nerrbuf:%s\n", errbuf);
		exit_main();
	}
	//打开保存的pcap文件	
	if( NULL==(des_pcap_dumper_t=pcap_dump_open(source_pcap_t,"./gl_icmp.pcap")) )
	{
		printf("pcap_dump_open() fail.\n");
		exit_main();		
	}
	struct bpf_program filter;
	char filter_str[30];
	snprintf(filter_str,sizeof(filter_str),"greater %d  and ip",mtu + MAC_HEAD +1);
	if( -1==pcap_compile(source_pcap_t, &filter, filter_str, 1, 0) )
	{
		printf("pcap_compile() fail.\n");
		printf("errno:%s\n", pcap_geterr(source_pcap_t));
		exit_main();
	}
	if( -1==pcap_setfilter(source_pcap_t, &filter) )
	{
		printf("pcap_setfilter() fail.\n");
		exit_main();
	}

	struct pcap_pkthdr *packet;
	const u_char *pktStr;
	int s=pcap_next_ex(source_pcap_t, &packet, &pktStr);
	while( s > 0 )
	{
		if( NULL==pktStr )
		{
			printf("pcap_next() return NULL.\n");
			break;		
		}
		else
		{

			const u_char *fcan_fragment = pktStr + 14 + 6;
			u_char can_fragment =(u_char) (fcan_fragment[0]>>5);
		//	printf("%d  \n ",can_fragment);
			u_short twovalue = (u_short)(fcan_fragment[0]<<8) + (u_short)fcan_fragment[1]; 
			u_short initoffset = twovalue & 0x1fff;
		//	printf("%d  \n", initoffset);

			if( can_fragment == 0 && initoffset == 0)
			{
				//		printf("Packet length: %d\n", packet->len);  
				//		printf("Number of bytes: %d\n", packet->caplen);  
				//		printf("Recieved time: %s\n", ctime((const time_t *)&packet->ts.tv_sec));
				pcap_dump((u_char*)des_pcap_dumper_t, packet, pktStr);	//读到的数据包写入生成pcap文件
			}

		}		
		s=pcap_next_ex(source_pcap_t, &packet, &pktStr);
	}

	pcap_dump_close(des_pcap_dumper_t);
	pcap_close(source_pcap_t);
}






void write_pcap()
{
	pcap_dumper_t *pdumper;
	char errbuf[PCAP_ERRBUF_SIZE]={0};
	if( NULL==(source_pcap_t=pcap_open_offline("gl_icmp.pcap", errbuf)) )
	{
		printf("pcap_open_offline() return NULL.\nerrbuf:%s\n", errbuf);
		exit_main();
	}
	//打开保存的pcap文件	
	if( NULL==(pdumper=pcap_dump_open(source_pcap_t,"./final.pcap")) )
	{
		printf("pcap_dump_open() fail.\n");
		exit_main();		
	}


	MyNode *p = list ->first;
	while(p)
	{
		Packet *packet = (Packet *)p->data;
		pcap_dump((u_char*)pdumper, packet->hdr, packet->data);
		p=p->next;
	}


	pcap_dump_flush(pdumper);
	pcap_dump_close(pdumper);
	pcap_close(source_pcap_t);

}



void free_data(void *data)
{
	Packet *packet = (Packet *)data;
	free(packet->hdr);
	free(packet->data);
}






int main(int argc, char *argv[])
{
	int opt;
	while ((opt = getopt(argc, argv, "m:")) != -1)
	{
		switch (opt) 
		{
			case 'm':
				mtu=atoi(optarg);
				//	printf("%d \n",mtu);
				break;
			case '?':
				printf("Unknown option: %c\n",(char)optopt);
				break;
		}

	}

	for(int i = optind; i < argc ; i++)
	{
		filter_pcap(argv[i]);
		list = createMyList();
		print_pcap("gl_icmp.pcap");	
		write_pcap();
	}
	if(list->length == 0) 
	printf("所有的包都不需要分片\n");
	else
	printf("\n%d \n", list->length);
	freeMyList(list,free_data);

	return 0;
}






