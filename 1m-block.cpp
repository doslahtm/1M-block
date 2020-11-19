#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h> /* for NF_ACCEPT */
#include <errno.h>
#include <libnet.h>
#include <set>
#include <iostream>
#include <fstream>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <string>

using namespace std;

uint32_t NF_VER = NF_ACCEPT; // last verdict
set<string> FilterSet;
char HostName[0x100];

void dump(unsigned char *buf, int size)
{
	int i;
	for (i = 0; i < size; i++)
	{
		if (i % 16 == 0)
			printf("\n");
		printf("%02x ", buf[i]);
	}
}

/* returns packet id */
static u_int32_t print_pkt(struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark, ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph)
	{
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			   ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph)
	{
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen - 1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen - 1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	
	if (((struct libnet_ipv4_hdr *)data)->ip_p == LIBNET_DHCP_DNS)
	{
		uint32_t ip_hdr_len = ((struct libnet_ipv4_hdr *)data)->ip_hl << 2; // ip header length
		uint32_t DataLen = ((struct libnet_ipv4_hdr *)data) ->ip_len; // ip packet length
		uint32_t tcp_hdr_len = ((struct libnet_tcp_hdr *)(data + ip_hdr_len))->th_off << 2; // tcp header length

		char *real_data = (char *)data + ip_hdr_len + tcp_hdr_len; // real data start pointer
		while ( *real_data == ' ' || *real_data == '\n' )
		{
			real_data++;
		}
		
		if (!memcmp("GET", real_data, 3) || !memcmp("POST", real_data, 4))
		{
			real_data += 3;
			while ( *real_data != '\r' )
			{
				real_data++;
			}
			real_data += 2;
			
			while (memcmp(real_data, "Host: ", 6))
				real_data += 1;
			real_data += 6;
			
			
			char *ptr = (char *)memchr(real_data, '\r', 0x100);
			memcpy(HostName, real_data, ptr - real_data);
			HostName[ptr - real_data] = '\0';
			set<string>::iterator iter;
			iter = FilterSet.find(HostName);
			if ( iter != FilterSet.end() )
			{
				NF_VER = NF_DROP;
			}
			else
			{
				NF_VER = NF_ACCEPT;
			}
		}
	}
	else
	{
		NF_VER = NF_ACCEPT;
	}
	

	if (ret >= 0)
	{
		printf("payload_len=%d ", ret);
		//dump(data, ret);
	}
	fputc('\n', stdout);

	return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
			  struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	printf("entering callback\n");
	return nfq_set_verdict(qh, id, NF_VER, 0, NULL);
}

void usage()
{
	printf("syntax : 1m-block <site list file>\n");
	printf("sample : 1m-block top-1m.txt\n");
	exit(0);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__((aligned));
	char c;
	if (argc != 2)
	{
		usage();
	}
	ifstream file;
	file.open(argv[1]);
	if ( !file.is_open() )
	{
		fprintf(stderr, "error during file open\n");
		exit(1);
	}

	while ( !file.eof() )
	{
		while (1)
		{
			file.get(c);
			if (c == ',')
				break;
		}
		string str;
		getline(file, str);
		FilterSet.insert(str);
	}
	file.close();
	printf("opening library handle\n");
	h = nfq_open();
	if (!h)
	{
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0)
	{
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0)
	{
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h, 0, &cb, NULL);
	if (!qh)
	{
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
	{
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;)
	{
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0)
		{
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS)
		{
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
