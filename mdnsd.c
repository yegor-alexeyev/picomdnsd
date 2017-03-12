/*
 * tinysvcmdns - a tiny MDNS implementation for publishing services
 * Copyright (C) 2011 Darell Tan
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>


#include "mdns.h"
#include "mdnsd.h"

#define LOG_ERR 3
#define PACKET_SIZE 65536
#define MDNS_PORT 5353
#include <sys/utsname.h>

#include <systemd/sd-daemon.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>


/*
 * Define a proper IP socket level if not already done.
 * Required to compile on OS X
 */
#ifndef SOL_IP
#define SOL_IP IPPROTO_IP
#endif

#include "mdns.h"
#include "mdnsd.h"

#define MDNS_ADDR "224.0.0.251"
#define MDNS_PORT 5353

#define PACKET_SIZE 65536

#define SERVICES_DNS_SD_NLABEL \
		((uint8_t *) "\x09_services\x07_dns-sd\x04_udp\x05local")

struct mdns_service {
	struct rr_list *entries;
};

static void log_message(int loglevel, char *fmt_str, ...) {
	va_list ap;
	char buf[2048];

	va_start(ap, fmt_str);
	vsnprintf(buf, 2047, fmt_str, ap);
	va_end(ap);
	buf[2047] = 0;

	fprintf(stderr, "%s\n", buf);
}


static ssize_t send_unicast_packet(int fd, const void *data, size_t len, struct sockaddr_in* toaddr) {
	return sendto(fd, data, len, 0, (struct sockaddr *) toaddr, sizeof(struct sockaddr_in));
}

static ssize_t send_packet(int fd, const void *data, size_t len) {
	static struct sockaddr_in toaddr;
	if (toaddr.sin_family != AF_INET) {
		memset(&toaddr, 0, sizeof(struct sockaddr_in));
		toaddr.sin_family = AF_INET;
		toaddr.sin_port = htons(MDNS_PORT);
		toaddr.sin_addr.s_addr = inet_addr(MDNS_ADDR);
	}

	return sendto(fd, data, len, 0, (struct sockaddr *) &toaddr, sizeof(struct sockaddr_in));
}


// populate the specified list which matches the RR name and type
// type can be RR_ANY, which populates all entries EXCEPT RR_NSEC
static int populate_answers(struct mdnsd *svr, struct rr_list **rr_head, uint8_t *name, enum rr_type type) {
	int num_ans = 0;

	// check if we have the records
	pthread_mutex_lock(&svr->data_lock);
	struct rr_group *ans_grp = rr_group_find(svr->group, name);
	if (ans_grp == NULL) {
		pthread_mutex_unlock(&svr->data_lock);
		return num_ans;
	}

	// decide which records should go into answers
	struct rr_list *n = ans_grp->rr;
	for (; n; n = n->next) {
		// exclude NSEC for RR_ANY
		if (type == RR_ANY && n->e->type == RR_NSEC)
			continue;

		if ((type == n->e->type || type == RR_ANY) && cmp_nlabel(name, n->e->name) == 0) {
			num_ans += rr_list_append(rr_head, n->e);
		}
	}

	pthread_mutex_unlock(&svr->data_lock);

	return num_ans;
}

// given a list of RRs, look up related records and add them
static void add_related_rr(struct mdnsd *svr, struct rr_list *list, struct mdns_pkt *reply) {
	for (; list; list = list->next) {
		struct rr_entry *ans = list->e;

		switch (ans->type) {
			case RR_PTR:
				// target host A, AAAA records
				reply->num_add_rr += populate_answers(svr, &reply->rr_add, 
										MDNS_RR_GET_PTR_NAME(ans), RR_ANY);
				break;

			case RR_SRV:
				// target host A, AAAA records
				reply->num_add_rr += populate_answers(svr, &reply->rr_add, 
										ans->data.SRV.target, RR_ANY);

				// perhaps TXT records of the same name?
				// if we use RR_ANY, we risk pulling in the same RR_SRV
				reply->num_add_rr += populate_answers(svr, &reply->rr_add, 
										ans->name, RR_TXT);
				break;

			case RR_A:
			case RR_AAAA:
				reply->num_add_rr += populate_answers(svr, &reply->rr_add, 
										ans->name, RR_NSEC);
				break;

			default:
				// nothing to add
				break;
		}
	}
}

// processes the incoming MDNS packet
// returns >0 if processed, 0 otherwise
static int process_mdns_pkt(struct mdnsd *svr, struct mdns_pkt *pkt, struct mdns_pkt *reply) {
	int i;

	assert(pkt != NULL);

	// is it standard query?
	if ((pkt->flags & MDNS_FLAG_RESP) == 0 && 
			MDNS_FLAG_GET_OPCODE(pkt->flags) == 0) {
		mdns_init_reply(reply, pkt->id);

		DEBUG_PRINTF("flags = %04x, qn = %d, ans = %d, add = %d\n", 
						pkt->flags,
						pkt->num_qn,
						pkt->num_ans_rr,
						pkt->num_add_rr);

		// loop through questions
		struct rr_list *qnl = pkt->rr_qn;
		for (i = 0; i < pkt->num_qn; i++, qnl = qnl->next) {
			struct rr_entry *qn = qnl->e;
			int num_ans_added = 0;

			char *namestr = nlabel_to_str(qn->name);
			DEBUG_PRINTF("qn #%d: type %s (%02x) %s - ", i, rr_get_type_name(qn->type), qn->type, namestr);
			free(namestr);

			// check if it's a unicast query - we ignore those
			if (qn->unicast_query) {
				DEBUG_PRINTF("skipping unicast query\n");
				continue;
			}

			num_ans_added = populate_answers(svr, &reply->rr_ans, qn->name, qn->type);
			reply->num_ans_rr += num_ans_added;

			DEBUG_PRINTF("added %d answers\n", num_ans_added);
		}

		// remove our replies if they were already in their answers
		struct rr_list *ans = NULL, *prev_ans = NULL;
		for (ans = reply->rr_ans; ans; ) {
			struct rr_list *next_ans = ans->next;
			struct rr_entry *known_ans = rr_entry_match(pkt->rr_ans, ans->e);

			// discard answers that have at least half of the actual TTL
			if (known_ans != NULL && known_ans->ttl >= ans->e->ttl / 2) {
				char *namestr = nlabel_to_str(ans->e->name);
				DEBUG_PRINTF("removing answer for %s\n", namestr);
				free(namestr);

				// check if list item is head
				if (prev_ans == NULL)
					reply->rr_ans = ans->next;
				else
					prev_ans->next = ans->next;
				free(ans);

				ans = prev_ans;

				// adjust answer count
				reply->num_ans_rr--;
			}

			prev_ans = ans;
			ans = next_ans;
		}


		// see if we can match additional records for answers
		add_related_rr(svr, reply->rr_ans, reply);

		// additional records for additional records
		add_related_rr(svr, reply->rr_add, reply);

		DEBUG_PRINTF("\n");

		return reply->num_ans_rr;
	}

	return 0;
}



/////////////////////////////////////////////////////


void mdnsd_set_hostname(struct mdnsd *svr, const char *hostname, uint32_t ip) {
	struct rr_entry *a_e = NULL,
					*nsec_e = NULL;

	// currently can't be called twice
	// dont ask me what happens if the IP changes
	assert(svr->hostname == NULL);

	a_e = rr_create_a(create_nlabel(hostname), ip);

	nsec_e = rr_create(create_nlabel(hostname), RR_NSEC);
	rr_set_nsec(nsec_e, RR_A);

	pthread_mutex_lock(&svr->data_lock);
	svr->hostname = create_nlabel(hostname);
	rr_group_add(&svr->group, a_e);
	rr_group_add(&svr->group, nsec_e);
	pthread_mutex_unlock(&svr->data_lock);
}

void mdnsd_add_rr(struct mdnsd *svr, struct rr_entry *rr) {
	pthread_mutex_lock(&svr->data_lock);
	rr_group_add(&svr->group, rr);
	pthread_mutex_unlock(&svr->data_lock);
}


void mdns_service_destroy(struct mdns_service *srv) {
	assert(srv != NULL);
	rr_list_destroy(srv->entries, 0);
	free(srv);
}

int main(int argc, char *argv[]) {

	char hostname[300];

  struct utsname buf;
  if (uname(&buf) != 0) {
        return 1;
  }

  int result = snprintf(hostname, sizeof(hostname), "%s.local", buf.nodename);

  if (result < 0 || result >= sizeof(hostname)) {
    return 1;
  }

  uint8_t pkt_buffer[PACKET_SIZE];
  struct mdns_pkt mdns_reply = {0};


  struct mdnsd server = {0};

  if (sd_listen_fds(0) != 1) {
		log_message(LOG_ERR, "failed check for passed file descriptors %d\n", sd_listen_fds(0));
    return 1;
  }
  server.sockfd = SD_LISTEN_FDS_START;

  struct ifaddrs *cursor;
  result = getifaddrs(&cursor);
  if ( result < 0 ) {
      log_message(LOG_ERR, "recv getifaddrs: %m");
      return 1;
  }

  while ( cursor != NULL ) {
    if ( cursor->ifa_addr->sa_family == AF_INET 
            && !(cursor->ifa_flags & IFF_LOOPBACK) 
            //&& !(cursor->ifa_flags & IFF_POINTOPOINT) 
            &&  (cursor->ifa_flags & IFF_MULTICAST) ) {

      uint32_t address = ((struct sockaddr_in *)cursor->ifa_addr)->sin_addr.s_addr;
      struct rr_entry *a2_e = rr_create_a(create_nlabel(hostname), address);
      mdnsd_add_rr(&server, a2_e);
      printf("added hostname %s = %s. \n", hostname, inet_ntoa((struct in_addr){address}));


    }
    cursor = cursor->ifa_next;
  }


  struct sockaddr_in fromaddr;
  socklen_t sockaddr_size = sizeof(struct sockaddr_in);

  ssize_t recvsize = recvfrom(server.sockfd, pkt_buffer, PACKET_SIZE, 0, 
    (struct sockaddr *) &fromaddr, &sockaddr_size);
  if (recvsize < 0) {
    log_message(LOG_ERR, "recv(): %m");
    return 0;
  }

  DEBUG_PRINTF("data from=%s size=%ld\n", inet_ntoa(fromaddr.sin_addr), (long) recvsize);
  struct mdns_pkt *mdns = mdns_parse_pkt(pkt_buffer, recvsize);
  if (mdns == NULL) {
    log_message(LOG_ERR, "failed to parse received data");
    return 0;
  }

  if (!process_mdns_pkt(&server, mdns, &mdns_reply)) {
    DEBUG_PRINTF("packet was not processed\n");
    if (mdns->num_qn == 0) {
      DEBUG_PRINTF("(no questions in packet)\n\n");
    }
    mdns_pkt_destroy(mdns);
    return 0;
  }

  size_t replylen = mdns_encode_pkt(&mdns_reply, pkt_buffer, PACKET_SIZE);
  if (fromaddr.sin_port == htons(MDNS_PORT)) {
    send_packet(server.sockfd, pkt_buffer, replylen);
  } else {
    //Legacy unicast response. https://tools.ietf.org/html/rfc6762#section-6.7
    send_unicast_packet(server.sockfd, pkt_buffer, replylen, &fromaddr);
  }

  mdns_pkt_destroy(mdns);

	return 0;
}

