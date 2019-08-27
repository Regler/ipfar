#include <pcap.h>
#include <stdlib.h>
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
u_char *data;
int length;
int mtu;
pcap_t *fp;


pcap_t *source_pcap_t=NULL;
pcap_dumper_t *des_pcap_dumper_t=NULL;
MyList *list=NULL;



void dispatcher_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	u_int i=0;
	
	//打印出数据包的数据
	length = header->caplen;
	data = (u_char *) malloc (sizeof(u_char) * length + 1);
	for (i=0; (i < header->caplen) ; i++)
	{
		printf("%.2x ", pkt_data[i]);
		data[i]=pkt_data[i];
		if ( (i % LINE_LEN) == 15) printf("\n");

	}
	myListInsertDataAtLast(list, data); 
	printf("\n\n");		

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
	if( -1==pcap_compile(source_pcap_t, &filter, "icmp", 1, 0) )
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
			printf("Packet length: %d\n", packet->len);  
			printf("Number of bytes: %d\n", packet->caplen);  
			printf("Recieved time: %s\n", ctime((const time_t *)&packet->ts.tv_sec));
			//读到的数据包写入生成pcap文件
			pcap_dump((u_char*)des_pcap_dumper_t, packet, pktStr);	
		}		
		s=pcap_next_ex(source_pcap_t, &packet, &pktStr);
	}

	pcap_dump_close(des_pcap_dumper_t);
	pcap_close(source_pcap_t);
}






void write_pcap( u_char *packet_data)
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

	struct pcap_pkthdr *hdr;
	hdr = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
	hdr->caplen = length;
	hdr->len = length;

	pcap_dump((u_char*)pdumper, hdr, packet_data);
	data[33] = 0x22; 
	pcap_dump((u_char*)pdumper, hdr, packet_data);


	pcap_dump_flush(pdumper);
	pcap_dump_close(pdumper);
	pcap_close(source_pcap_t);

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
				printf("%d \n",mtu);
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
		write_pcap(data);
	}
	printf("\n%d \n", list->length);


	return 0;
}






