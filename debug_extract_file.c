/* Author: Diyo Davis */

#include<pcap/pcap.h>
#include<net/ethernet.h>
#include<linux/ip.h>
#include<linux/tcp.h>
#include<string.h>
#include<stdlib.h>
#include<arpa/inet.h>
#include<sys/types.h>
#include<fcntl.h>
#include<unistd.h>
//#include<errno.h>

struct ether_header *eth = NULL;
struct iphdr *ip = NULL;
struct tcphdr *tcp = NULL;
char *payload = NULL;

int count,flag,fd,ret = 0;
int hdr_len = sizeof(struct ether_header) + sizeof(struct iphdr);
unsigned long size,wr = 0;

void process_packet(u_char *user, const struct pcap_pkthdr *h,const u_char *bytes){
	printf("pkt no is %d && caplen is %d\n", ++count, h->caplen);

	/*for(int i = 0; i < h->caplen; i++){
		printf("%02x ",bytes[i]);
	}*/

	eth = (struct ether_header *)(bytes);
	
	//printf("type=%d\n",eth->ether_type);
	if(ntohs(eth->ether_type) != 2048)	return;

	ip = (struct iphdr *)(bytes + sizeof(struct ether_header));

	//printf("proto=%d\n", ip->protocol);
	if(ip->protocol != 6)	return;

	tcp = (struct tcphdr *)(bytes + sizeof(struct ether_header) + sizeof(struct iphdr));
	//printf("tcp_offset=%d tcp_hdr_len=%d\n", tcp->doff, 4 * tcp->doff);
	int pkt_len = ntohs(ip->tot_len) - sizeof(struct iphdr);
	//printf("hdr_len=%d pkt_len=%d\n", hdr_len, pkt_len);
	int payload_len = h->caplen - (hdr_len + 4 * tcp->doff);
	payload = (char *)malloc(payload_len);
	memset(payload,'\0',payload_len);
	//printf("\nalloc=%d bytes\n",h->caplen - (hdr_len + 4 * tcp->doff));
	char * payload_offset = bytes + hdr_len + 4 * tcp->doff;
	//printf("\n%s\n",strncpy(cmd,payload_offset,4));
	
	//if(!strncmp("226",payload_offset,3) && !strncmp("Transfer complete.",payload_offset + 4,sizeof("Transfer complete.")))
	//	flag = 0;

	if(!strncmp("SIZE",payload_offset,4)){
		size = 1;
		return;
	}

	if(!strncmp("213",payload_offset,3) && size == 1){
		size = strtoul(payload_offset + 4, NULL, 10);
		printf("size=%lu\n",size);
	}

	if(!strncmp("RETR",payload_offset,4)){
		//printf("\npl_before=%d\n", payload_len);
		payload_len = payload_len - 7;
		//printf("\npl_after=%d\n", payload_len);
		char *fname = (char *)malloc(payload_len);
		memset(fname,'\0',payload_len);
		strncpy(fname, payload_offset + 5, payload_len);
		//printf("\n%s --> %ld\n",fname,sizeof(fname));
		//printf("here\n");
		//printf("%s\n",strrchr(fname, '/') + 1);
		if(strrchr(fname, '/') == NULL)
			fd = open(fname, O_CREAT | O_WRONLY | O_TRUNC, 0777);
		else	fd = open(strrchr(fname, '/') + 1, O_CREAT | O_WRONLY | O_TRUNC, 0777);
		/*if((fd = open(fname, O_CREAT | O_WRONLY | O_TRUNC, 0777)) < 0)
			perror("file creation failed");
		else	printf("\nfile created\n");*/
		free(fname);
		ret = 1;
		return;
	}
	
	if(flag == 1 && payload_len != 0){
		//strncpy(payload,payload_offset,payload_len);
		//printf("%s\n",payload);
		ret = write(fd,payload_offset,payload_len);
		//if(count == 2126)	exit(0);
		/*printf("\ncontent begins\n");
		int i = hdr_len + 4 * tcp->doff;
		int j = 64;
		printf("%04x --> 58 9f %02x %02x %02x %02x %02x %02x  ",j,bytes[i],bytes[i+1],bytes[i+2],bytes[i+3],bytes[i+4],bytes[i+5]);
		printf("%02x %02x %02x %02x %02x %02x %02x %02x\n",bytes[i+6],bytes[i+7],bytes[i+8],bytes[i+9],bytes[i+10],bytes[i+11],bytes[i+12],bytes[i+13]);
		for(i = (hdr_len + 4 * tcp->doff) + 14; i < payload_len; i=i+16,j=j+16){
			printf("%04x --> %02x %02x %02x %02x %02x %02x %02x %02x  ",j+16,bytes[i],bytes[i+1],bytes[i+2],bytes[i+3],bytes[i+4],bytes[i+5],bytes[i+6],bytes[i+7]);
			printf("%02x %02x %02x %02x %02x %02x %02x %02x\n",bytes[i+8],bytes[i+9],bytes[i+10],bytes[i+11],bytes[i+12],bytes[i+13],bytes[i+14],bytes[i+15]);
		}
		printf("%04x --> %02x %02x %02x %02x %02x %02x %02x %02x  ",j+16,bytes[i],bytes[i+1],bytes[i+2],bytes[i+3],bytes[i+4],bytes[i+5],bytes[i+6],bytes[i+7]);
		printf("\ncontent ends\n");*/

		printf("wrote from pkt %d bytes\n",ret);
		wr += ret;
		if(wr == size){
			//printf("wr=%lu size=%lu\n", wr, size);
			flag = 0;
			ret = 0;
			wr = 0;
			close(fd);
		}
		/*if(write(fd,payload,payload_len) < 0)
			printf("writing to file failed : %d\n",errno);
		else	printf("\nwritten %d bytes to file\n",ret);*/
	}

	if((!strncmp("150",payload_offset,3)) && (ret == 1)){
		flag = 1;
		ret = 0;
		return;
	}
	
	//printf("\n\npayload begins\n\n%s\n\npayload ends\n\n",payload);
	//printf("%s\n",payload);
	memset(payload,'\0',payload_len);
	free(payload);
	printf("---------------------------------------------------------------------\n");
}

int main(){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = NULL;
	handle = pcap_open_offline("./file_capture_multiple.pcap", errbuf);
	pcap_loop(handle, -1, process_packet, NULL);
	return 0;
}