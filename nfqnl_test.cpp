#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <string.h>
#include <string>
#include <stdint.h>
#include <unordered_set>

std::unordered_set<std::string> domains;

struct ip_header {
    uint8_t ihl:4,ip_v:4;
    uint8_t  tos;
    uint16_t len;
    uint16_t id;
    uint16_t offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t saddr;
    uint32_t daddr;
};

struct tcp_header {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack;
    uint8_t rev:4,offset:4;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;
};

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    struct nfqnl_msg_packet_hdr *ph;
    uint8_t *packet;
    int len;

    ph = nfq_get_msg_packet_hdr(nfa);
    len = nfq_get_payload(nfa, &packet);
    
    
    if(len >= sizeof(struct ip_header)) { // minimum ip hedaer len
        struct ip_header *iph = (struct ip_header *)packet;
        if(iph->protocol == 6) { // 6 is tcp
            struct tcp_header *tcph = (struct tcp_header *)(packet + (iph->ihl*4));

            if(ntohs(tcph->dport) == 80) {
                char *data = (char *)(packet + (iph->ihl*4) + (tcph->offset*4));
				
				for(int i =0;i <len; i++){
					if(memcmp(data+i,"Host: ",6)==0){
						if(memcmp(data+i+6,"test.gilgil.net",15)==0)
						{
                            printf("detect\n");
							return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_DROP, 0, NULL);
						}
					}
				}
            }
        }
    }
    return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, 0, NULL);
}

int main(int argc, char* argv[])
{
    FILE* file = fopen("top-m.csv","r");
    char tmp[256];
    while(fgets(tmp,sizeof(tmp),file)){
        char* comma = strchr(tmp,',');
        if(comma){
            char* tmp_domain = comma + 1;
            tmp_domain[strcspn(tmp_domain,"\n")] = 0;
            domains.insert(std::string(tmp_domain));
        }


    }




    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    h = nfq_open();
    

    nfq_unbind_pf(h, AF_INET);
    nfq_bind_pf(h, AF_INET);

    qh = nfq_create_queue(h, 0, &cb, NULL);

	nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff);

    fd = nfq_fd(h);

    while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
        nfq_handle_packet(h, buf, rv);
    }

    nfq_destroy_queue(qh);
    nfq_close(h);
}