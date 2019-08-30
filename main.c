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
int mtu = 1500;
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
		sum += (u_int)p;
	}
	u_short  d = (u_short)sum;
	u_short  f = (u_short)(sum>>16);
	u_short s =(u_short)(d + f);
	return  s;
}



void dispatcher_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data)
{

	if((mtu - IP_HEAD)%8 != 0)
		mtu = mtu - (mtu - IP_HEAD)%8;

	int num_ip_fragment = (header->len - MAC_HEAD - IP_HEAD - 1 )/(mtu - IP_HEAD) + 1;
	//	printf("num_ip_fragment = %d\n", num_ip_fragment);



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
			check[1]= ~((u_short)finalchecknum);
			check[0] = ~((u_short)(finalchecknum>>8));


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
			check[1]= ~((u_short)finalchecknum);
			check[0] = ~((u_short)(finalchecknum>>8));

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





void packet_to_node(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data)
{

	Packet *packet = (Packet *)malloc(sizeof(Packet));

	packet->data = (u_char *) malloc (sizeof(u_char) *(header->len) + 1);
	packet->hdr = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));

	packet->hdr->len = header->len;
	packet->hdr->caplen = header->caplen ;
	packet->hdr->ts.tv_sec = header->ts.tv_sec;
	packet->hdr->ts.tv_usec = header->ts.tv_usec;
	int j;
	for (j = 0; j < header->len; j++)
		packet->data[j] = pkt_data[j];
	packet->data[j]='\0';

	myListInsertDataAtLast(list, packet); 

}

void pcap_to_list(char *file)
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
	pcap_loop(fp, 0, packet_to_node, NULL);
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
			u_short twovalue = (u_short)(fcan_fragment[0]<<8) + (u_short)fcan_fragment[1]; 
			u_short initoffset = twovalue & 0x1fff;

			if( can_fragment == 0 && initoffset == 0)
			{
				pcap_dump((u_char*)des_pcap_dumper_t, packet, pktStr);	//读到的数据包写入生成pcap文件
			}

		}		
		s=pcap_next_ex(source_pcap_t, &packet, &pktStr);
	}

	/*
	if(source_pcap_t)
	{
		free(source_pcap_t);
		source_pcap_t = NULL;
	}
	*/

	pcap_dump_close(des_pcap_dumper_t);
	pcap_close(source_pcap_t);
}






void write_pcap( pcap_dumper_t *pdumper)
{

	MyNode *p = list ->first;
	while(p)
	{
		Packet *packet = (Packet *)p->data;
		pcap_dump((u_char*)pdumper, packet->hdr, packet->data);
		p=p->next;
	}
}


void write_packet(pcap_dumper_t *pdumper, Packet *packet)
{
	pcap_dump((u_char*)pdumper, packet->hdr, packet->data);
}






void free_data(void *data)
{
	Packet *packet = (Packet *)data;
	free(packet->hdr);
	free(packet->data);
}



void packet_handler(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data)
{
	pcap_dump(user, pkt_header, pkt_data);// 输出数据到文件
	printf("get a packet with length of [%d]\n", pkt_header->len);// 打印抓到的包的长度
}

void autogetpacket()
{

	pcap_t *handle;                 // 会话句柄 

	char errbuf[PCAP_ERRBUF_SIZE]; // 存储错误信息的字符串

	bpf_u_int32 mask;               //所在网络的掩码 
	bpf_u_int32 net;                // 主机的IP地址 

	struct bpf_program filter;      //已经编译好的过滤器
	char filter_app[] = "ip";  //BPF过滤规则,和tcpdump使用的是同一种过滤规则

	/* 探查设备及属性 */
	char *dev;                      //指定需要被抓包的设备 我们在linux下的两个设备eth0和lo分别是网卡和本地环回
	dev = pcap_lookupdev(errbuf);   //返回第一个合法的设备，我这里是eth0
	pcap_lookupnet(dev, &net, &mask, errbuf);
	printf("dev =  %s\n",dev);
	//dev = "lo";                   //如果需要抓取本地的数据包，比如过滤表达式为host localhost的时候可以直接指定

	/* 以混杂模式打开会话 */
	handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);

	/* 编译并应用过滤器 */
	pcap_compile(handle, &filter, filter_app, 0, net);
	pcap_setfilter(handle, &filter);

	/* 定义输出文件 */
	pcap_dumper_t* out_pcap;
	out_pcap  = pcap_dump_open(handle,"./autogetpacket.pcap");
	

	/* 截获30个包 */
	pcap_loop(handle,30,packet_handler,(u_char *)out_pcap);

	/* 刷新缓冲区 */
	pcap_dump_flush(out_pcap);

	/* 关闭资源 */
	pcap_close(handle);
	pcap_dump_close(out_pcap);

}



int packet_len(MyList *list)
{
	int len = 0;
	MyNode * p = list->first;
	while(p != NULL)
	{
		len += ((Packet *)p->data)->hdr->caplen;
		p = p->next;
	}
	int final_len = len - (list->length-1) * 34;
	return final_len;
}



Packet *chongzu(MyList *list)
{
	Packet *final_packet = (Packet *)malloc(sizeof(Packet));

	int final_len = packet_len(list);


	final_packet->data = (u_char *) malloc (sizeof(u_char)*(final_len + 1));
	final_packet->hdr = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));

	MyNode * p = list->first;

	final_packet->hdr->len = final_len;
	final_packet->hdr->caplen = final_len;
	final_packet->hdr->ts.tv_sec = ((Packet *)p->data)->hdr->ts.tv_sec;
	final_packet->hdr->ts.tv_usec = ((Packet *)p->data)->hdr->ts.tv_usec;

	int j;
	int index = 0 ;

	for (j = 0; j < MAC_HEAD + IP_HEAD; j++)
		final_packet->data[index++] = ((Packet *)p->data)->data[j];

	u_char *flength = final_packet->data + 14 + 2;
	u_short packet_length = (u_short)(final_len - MAC_HEAD) ; 
	flength[1] = (u_char)(packet_length);
	flength[0] = (u_short)(packet_length>>8);

	u_char *foffset= final_packet->data + 14 + 6;
	foffset[0] = 0x00;
	foffset[1] = 0x00;

	u_char *check = final_packet->data + 14 + 10;
	check[0] = 0x00;
	check[1] = 0x00;
	u_short finalchecknum = checknum(final_packet->data + 14, 20);
	check[1]= ~((u_short)finalchecknum);
	check[0] = ~((u_short)(finalchecknum>>8));



	while(p != NULL)
	{
		Packet * packet = (Packet *) p->data;
		int len = packet->hdr->caplen;
		for(int i = MAC_HEAD + IP_HEAD;i <len ;i++)
		{
			final_packet->data[index++] = packet->data[i];
		}
		p = p->next;
	}
	final_packet->data[index] = '\0';
	return final_packet;
}



void cz()
{
	list = createMyList();

	pcap_to_list("cz.pcap");

	Packet *packet = chongzu(list);

	pcap_dumper_t *pdumper6;
	char errbuf[PCAP_ERRBUF_SIZE]={0};
	pcap_t *source_pcap_t6 = NULL;
	if( NULL==(source_pcap_t6=pcap_open_offline("gl_icmp.pcap", errbuf)) )
	{
		printf("pcap_open_offline() return NULL.\nerrbuf:%s\n", errbuf);
		exit_main();
	}
	//打开保存的pcap文件	
	if( NULL==(pdumper6=pcap_dump_open(source_pcap_t6,"./czfinal.pcap")) )
	{
		printf("pcap_dump_open() fail.\n");
		exit_main();		
	}


	write_packet(pdumper6, packet);

	pcap_dump_flush(pdumper6);
	pcap_dump_close(pdumper6);
	pcap_close(source_pcap_t6);


}


void fp_packet(char *filename,pcap_dumper_t *pdumper)
{
	filter_pcap(filename);
	list = createMyList();
	print_pcap("gl_icmp.pcap");	
	write_pcap(pdumper);
	if(list->length == 0) 
		printf("所有的包都不需要分片\n");
	else
		printf("\n%d \n", list->length);
	freeMyList(list,free_data);


}




int main(int argc, char *argv[])
{
	int opt;
	int is_autogetpacke = 0;
	int is_foc = 0;
	while ((opt = getopt(argc, argv, "m:ac")) != -1)
	{
		switch (opt) 
		{
			case 'm':
				mtu=atoi(optarg);
				//	printf("%d \n",mtu);
				break;
			case 'a':
				autogetpacket();
				is_autogetpacke = 1;
				break;
			case 'c':
				cz();
				is_foc = 1;
					break;
			case '?':
				printf("Unknown option: %c\n",(char)optopt);
				break;
		}

	}

	if( is_foc == 0)
	{
		pcap_dumper_t *pdumper;
		char errbuf[PCAP_ERRBUF_SIZE]={0};
		pcap_t *source_pcap_t1 = NULL;
		if( NULL==(source_pcap_t1=pcap_open_offline("gl_icmp.pcap", errbuf)) )
		{
			printf("pcap_open_offline() return NULL.\nerrbuf:%s\n", errbuf);
			exit_main();
		}
		//打开保存的pcap文件	
		if( NULL==(pdumper=pcap_dump_open(source_pcap_t1,"./final.pcap")) )
		{
			printf("pcap_dump_open() fail.\n");
			exit_main();		
		}
		
		if(is_autogetpacke == 0)
		{
			for(int i = optind; i < argc ; i++)
			{
				fp_packet(argv[i],pdumper);
			}
		}
		else 
		{
			fp_packet("./autogetpacket.pcap",pdumper);
		}
/*
		if(source_pcap_t1)
		{
			free(source_pcap_t1);
			source_pcap_t1 = NULL ;
		}*/
		pcap_dump_flush(pdumper);
		pcap_dump_close(pdumper);
		pcap_close(source_pcap_t1);
	}


	return 0;

}






