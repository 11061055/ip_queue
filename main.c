#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/tcp.h>
#include <sys/socket.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libipq.h"

#define BUFSIZE 2048

struct tcp_pseudo_hdr
{
  unsigned int src;
  unsigned int dst;
  unsigned char zero;
  unsigned char proto;
  unsigned short length;
};

unsigned short csum (void *addr, int len)
{
  register unsigned short *idx = addr;
  register unsigned int sum = 0;

  while (len > 1)
  {
      sum += *idx++;
      len -= 2;
  }

  if (len == 1) {
    sum += htons (*(unsigned char *) idx << 8);
  }

  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  sum = ~sum;
  return (unsigned short)sum;
}


unsigned short tcp_csum (struct iphdr *iph, struct tcphdr *tcph)
{
  char tcp_csum_buf[BUFSIZE + sizeof(struct tcp_pseudo_hdr)];

  int ip_total_len   = ntohs(iph->tot_len);
  int ip_header_len  = iph->ihl * 4;

  int tcp_header_len = sizeof (struct tcphdr); // = 20
  int tcp_option_len = tcph->doff * 4 - tcp_header_len;
  int tcp_data_len   = ip_total_len - ip_header_len - tcp_header_len - tcp_option_len;
  int tcp_total_len  = tcp_header_len + tcp_option_len + tcp_data_len;

  int pseudo_header_len = sizeof(struct tcp_pseudo_hdr);

  struct tcp_pseudo_hdr pseudo_hdr;

  pseudo_hdr.src = iph->saddr;
  pseudo_hdr.dst = iph->daddr;
  pseudo_hdr.zero = 0;
  pseudo_hdr.proto = IPPROTO_TCP;
  pseudo_hdr.length = htons (tcp_total_len);

  int tcp_len_to_csum = sizeof (struct tcp_pseudo_hdr) + tcp_total_len;

  memcpy (tcp_csum_buf, (unsigned char *)&pseudo_hdr, pseudo_header_len);
  memcpy (tcp_csum_buf + pseudo_header_len,
	  (unsigned char *) tcph, tcp_header_len);
  memcpy (tcp_csum_buf + pseudo_header_len + tcp_header_len,
	  (unsigned char *) tcph + tcp_header_len,
	  tcp_option_len);
  memcpy (tcp_csum_buf + pseudo_header_len + tcp_header_len + tcp_option_len,
	  (unsigned char *) tcph + tcp_header_len + tcp_option_len, tcp_data_len);

  return csum (tcp_csum_buf, tcp_len_to_csum);
}


void main (int argc, char **argv)
{
  int status;
  unsigned char buf[BUFSIZE];

  struct ipq_handle *handle = ipq_create_handle (0, PF_INET);

  if (!handle)
  {
    fprintf(stderr,"create handle error\n");
    return;
  }

  status = ipq_set_mode (handle, IPQ_COPY_PACKET, BUFSIZE);
  if (status < 0)
  {
    fprintf(stderr,"ipq set mode error\n");
    return;
  }

  do
  {
      status = ipq_read (handle, buf, BUFSIZE, 0);
      if (status < 0)
      {
         fprintf(stderr, "read error\n");
         return;
      }

      switch (ipq_message_type (buf))
      {
	case NLMSG_ERROR:
	  fprintf (stderr, "Received error message %d\n", ipq_get_msgerr (buf));
	  break;

	case IPQM_PACKET:
	{
	    ipq_packet_msg_t *msg = ipq_get_packet (buf);

	    fprintf (stderr, "Received packet (size: %d).\n", msg->data_len);

	    struct iphdr *iph = ((struct iphdr *) msg->payload);

	    struct tcphdr *tcph;

	    if (iph->protocol != IPPROTO_TCP)
	    {
		// ! TCP IS ACCEPTED Unconditionally

		status = ipq_set_verdict (handle, msg->packet_id, NF_ACCEPT, 0, NULL);
		if (status < 0)
		{
	    	  fprintf (stderr, "ipq set verdict error.\n");
		}
		break;

	    }

 	    // change destination ip here
	    iph->daddr = inet_addr("111.202.103.60");

	    tcph = (struct tcphdr *) (msg->payload + (iph->ihl << 2));

	    tcph->check = 0;
	    tcph->check = tcp_csum (iph, tcph);

	    iph->check = 0;
	    iph->check = csum (iph, iph->ihl * 4);

	    status = ipq_set_verdict (handle, msg->packet_id, NF_ACCEPT, msg->data_len, msg->payload);

	    if (status < 0)
	    {
	    	fprintf (stderr, "ipq set verdict error.\n");
		return;
	    }
	    break;
 	}

	default:
	  fprintf (stderr, "Unknown message type!\n");
	  break;
	}

    } while (1);

    ipq_destroy_handle (handle);
}
