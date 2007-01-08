/*
 * flow.c --
 *
 * The functions in this module identify SNMP flows.
 *
 * Copyright (c) 2006 Juergen Schoenwaelder
 *
 * $Id$
 */

#define _GNU_SOURCE

#include "config.h"
#include "snmp.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/resource.h>

#define SNMP_FLOW_NONE		0x00
#define SNMP_FLOW_COMMAND	0x01
#define SNMP_FLOW_NOTIFY	0x02

typedef struct _snmp_flow_elem {
    snmp_packet_t	   *pkt;
    struct _snmp_flow_elem *next;
} snmp_flow_elem;

typedef struct _snmp_flow {
    int			type;
    char		*name;
    snmp_ipaddr_t       src_addr;
    snmp_ip6addr_t      src_addr6;
    snmp_uint32_t	src_port;
    snmp_ipaddr_t       dst_addr;
    snmp_ip6addr_t      dst_addr6;
    snmp_uint32_t	dst_port;
    uint64_t		cnt;
    FILE		*stream;
    snmp_flow_elem	*list;
    struct _snmp_flow	*next;
} snmp_flow_t;

static snmp_flow_t *flow_list = NULL;

typedef struct _snmp_cache_elem {
    snmp_packet_t *pkt;
    struct _snmp_cache_elem *next;
    struct _snmp_cache_elem *kids;
} snmp_cache_elem_t;

static snmp_cache_elem_t *snmp_cache_list = NULL;

static inline void*
xmalloc(size_t size)
{
    void *p;

    p = malloc(size);
    if (! p) {
	abort();
    }
    memset(p, 0, size);
    return p;
}

/*
 * Create a name for a flow file name. The name is dynamically
 * allocated and must be freed by the caller when he is done with it.
 */

static char*
snmp_flow_name(snmp_flow_t *flow)
{
    char *name;
    const char *src = NULL, *dst = NULL;
    char src_addr[INET_ADDRSTRLEN], dst_addr[INET_ADDRSTRLEN];
    char src_addr6[INET6_ADDRSTRLEN], dst_addr6[INET6_ADDRSTRLEN];
#define FLOW_NAME_SIZE 128

    name = xmalloc(FLOW_NAME_SIZE);

    if (flow->src_addr6.attr.flags & SNMP_FLAG_VALUE) {
	src = inet_ntop(AF_INET6,
			&flow->src_addr6.value, src_addr6, sizeof(src_addr6));
    }
    if (flow->dst_addr6.attr.flags & SNMP_FLAG_VALUE) {
	dst = inet_ntop(AF_INET6,
			&flow->dst_addr6.value, dst_addr6, sizeof(dst_addr6));
    }
    
    if (flow->src_addr.attr.flags & SNMP_FLAG_VALUE) {
	src = inet_ntop(AF_INET,
			&flow->src_addr.value, src_addr, sizeof(src_addr));
    }
    if (flow->dst_addr.attr.flags & SNMP_FLAG_VALUE) {
	dst = inet_ntop(AF_INET,
			&flow->dst_addr.value, dst_addr, sizeof(dst_addr));
    }

    if (! src || ! dst) {
	free(name);
	return NULL;
    }
    
    snprintf(name, FLOW_NAME_SIZE, "%s-%s-%s-%s",
	     (flow->type == SNMP_FLOW_COMMAND) ? "cg" : "no",
	     src ? src : "xxx",
	     (flow->type == SNMP_FLOW_COMMAND) ? "cr" : "nr",
	     dst ? dst : "yyy");
    
    return name;	
}

/*
 * Helper function to test whether two IPv4 addresses are equal.
 */

static inline int
snmp_ipaddr_equal(snmp_ipaddr_t *a, snmp_ipaddr_t *b)
{
    return (a->attr.flags & SNMP_FLAG_VALUE
	    && b->attr.flags & SNMP_FLAG_VALUE
	    && memcmp(&a->value, &b->value, 4) == 0);
}

/*
 * Helper function to test whether two IPv6 addresses are equal.
 */

static inline int
snmp_ip6addr_equal(snmp_ip6addr_t *a, snmp_ip6addr_t *b)
{
    return (a->attr.flags & SNMP_FLAG_VALUE
	    && b->attr.flags & SNMP_FLAG_VALUE
	    && memcmp(&a->value, &b->value, 16) == 0);
}

/*
 * Helper function to test whether two int32 values are equal.
 */

static inline int
snmp_int32_equal(snmp_int32_t *a, snmp_int32_t *b)
{
    return (a->attr.flags & SNMP_FLAG_VALUE
	    && b->attr.flags & SNMP_FLAG_VALUE
	    && a->value == b->value);
}

/*
 * Helper function to test whether two uint32 values are equal.
 */

static inline int
snmp_uint32_equal(snmp_uint32_t *a, snmp_uint32_t *b)
{
    return (a->attr.flags & SNMP_FLAG_VALUE
	    && b->attr.flags & SNMP_FLAG_VALUE
	    && a->value == b->value);
}

/*
 * Compare two time stamps. This function returns a value less than 0
 * if a < b, the value 0 if a == b, and a value > 0 if a > b.
 */

static inline int
snmp_timestamp_compare(uint32_t a_sec, uint32_t a_usec,
		       uint32_t b_sec, uint32_t b_usec)
{
    if (a_sec < b_sec) {
	return -1;
    }

    if (a_sec > b_sec) {
	return 1;
    }
    
    if (a_sec == b_sec) {
	if (a_usec < b_usec) {
	    return -1;
	}
	if (a_usec < b_usec) {
	    return 1;
	}
    }

    return 0;
}

/*
 * Add a new packet to the cache of recently seen packets.
 */

static snmp_cache_elem_t*
snmp_cache_add(snmp_cache_elem_t *list, snmp_packet_t *pkt)
{
    snmp_cache_elem_t *p;

    p = xmalloc(sizeof(snmp_cache_elem_t));
    p->pkt = snmp_pkt_copy(pkt);
    p->next = list;
    return p;
}

/*
 * Remove all elements from the cache list that are older than the
 * given time stamp. Since we add new packets at the front of the
 * list, we basically have to traverse the list until we find old
 * packets and then we can discard the tail. Perhaps a smarter data
 * structure should be used to scale to very bursty SNMP traces...
 */

static snmp_cache_elem_t*
snmp_cache_expire(snmp_cache_elem_t *list,
		  uint32_t ts_sec, uint32_t ts_usec)
{
    snmp_cache_elem_t *p = list, *l = NULL, *x;
    
    while (p) {
	if (snmp_timestamp_compare(p->pkt->time_sec.value,
				   p->pkt->time_usec.value,
				   ts_sec, ts_usec) < 0) {
	    x = p;
	    if (l) {
		l->next = p->next;
	    } else {
		list = p->next;
	    }
	    p = p->next;
	    if (x->pkt) {
		snmp_pkt_delete(x->pkt);
		x->pkt = NULL;
	    }
	    free(x);
	} else {
	    l = p; p = p->next;
	}
    }

    return list;
}

/*
 * For a given packet pkt, find a suitable matching packet in the
 * cache.
 */

static snmp_cache_elem_t*
snmp_cache_find(snmp_cache_elem_t *list, snmp_packet_t *pkt)
{
    snmp_cache_elem_t *p;

    for (p = list; p; p = p->next) {
	if (snmp_int32_equal(&p->pkt->snmp.scoped_pdu.pdu.req_id,
			     &pkt->snmp.scoped_pdu.pdu.req_id)
	    
	    /* xxx what about ipv6 addresses ??? */

	    /* xxx if I comment out the first ip address check, things
	     * behave very strange; we loose packets in unknown (kind
	     * of expected, but they do not show up elsewhere and in
	     * addition I saw an empty line in the unknown file and I
	     * have no clue where this is coming from xxx */
	     
	    && snmp_ipaddr_equal(&p->pkt->dst_addr, &pkt->src_addr)
	    && snmp_uint32_equal(&p->pkt->src_port, &pkt->dst_port)
	    && snmp_ipaddr_equal(&p->pkt->src_addr, &pkt->dst_addr)) {
	    return p;
	}
    }

    return NULL;
}

static inline int
snmp_flow_type(snmp_packet_t *pkt)
{
    int type = SNMP_FLOW_NONE;
    
    if (! pkt->snmp.scoped_pdu.pdu.attr.flags & SNMP_FLAG_VALUE) {
	return SNMP_FLOW_NONE;
    }

    switch (pkt->snmp.scoped_pdu.pdu.type) {
    case SNMP_PDU_GET:
    case SNMP_PDU_GETNEXT:
    case SNMP_PDU_GETBULK:
    case SNMP_PDU_SET:
	type = SNMP_FLOW_COMMAND;
	break;
    case SNMP_PDU_RESPONSE:
	type = SNMP_FLOW_NONE;
	break;
    case SNMP_PDU_TRAP1:
    case SNMP_PDU_TRAP2:
    case SNMP_PDU_INFORM:
	type = SNMP_FLOW_NOTIFY;
	break;
    case SNMP_PDU_REPORT:
	type = SNMP_FLOW_NONE;
	break;
    }

    return type;
}

/*
 * Find a flow, potentially creating new flows if a flow does not yet
 * exist.
 */

static snmp_flow_t*
snmp_flow_find(snmp_packet_t *pkt)
{
    snmp_flow_t *p;
    snmp_cache_elem_t *e;
    int type;
    int reverse = 0;

    type = snmp_flow_type(pkt);

    /*
     * If we have a report or a response, we try to find the
     * corresponding request in the list of recently seen requests. If
     * we find the request, we can set the flow type. If we are
     * unsuccessful, we return that we were unable to identify the
     * flow to which this packet belongs.
     */

    if (type == SNMP_FLOW_NONE) {
	e = snmp_cache_find(snmp_cache_list, pkt);
	if (e && e->pkt->snmp.scoped_pdu.pdu.attr.flags & SNMP_FLAG_VALUE) {
	    type = snmp_flow_type(e->pkt);
	    reverse = 1;
	}
    }

    if (type == SNMP_FLOW_NONE) {
	return NULL;
    }

    /*
     * Now we know the flow. Lookup a flow entry or create a new one
     * if there is no appropriate flow entry yet.
     */

    for (p = flow_list; p; p = p->next) {
	if (p->type == type
	    && snmp_ipaddr_equal(&p->src_addr,
				 reverse ? &pkt->dst_addr : &pkt->src_addr)
	    && snmp_ipaddr_equal(&p->dst_addr,
				 reverse ? &pkt->src_addr : &pkt->dst_addr)) {
	    break;
	}
	if (p->type == type
	    && snmp_ip6addr_equal(&p->src_addr6,
				  reverse ? &pkt->dst_addr6 : &pkt->src_addr6)
	    && snmp_ip6addr_equal(&p->dst_addr6,
				  reverse ? &pkt->src_addr6 : &pkt->dst_addr6)) {
	    break;
	}
    }

    if (! p) {
	p = xmalloc(sizeof(snmp_flow_t));
	p->type = type;
	if (pkt->src_addr.attr.flags & SNMP_FLAG_VALUE
	    && pkt->dst_addr.attr.flags & SNMP_FLAG_VALUE) {
	    memcpy(&p->src_addr, &pkt->src_addr, sizeof(p->src_addr));
	    memcpy(&p->dst_addr, &pkt->dst_addr, sizeof(p->dst_addr));
	}
	if (pkt->src_addr6.attr.flags & SNMP_FLAG_VALUE
	    && pkt->dst_addr6.attr.flags & SNMP_FLAG_VALUE) {
	    memcpy(&p->src_addr6, &pkt->src_addr6, sizeof(p->src_addr6));
	    memcpy(&p->dst_addr6, &pkt->dst_addr6, sizeof(p->dst_addr6));
	}
	memcpy(&p->src_port, &pkt->src_port, sizeof(p->src_port));
	memcpy(&p->dst_port, &pkt->dst_port, sizeof(p->dst_port));
	p->name = snmp_flow_name(p);
	p->next = flow_list;
	flow_list = p;
    }
    return p;
}

/*
 * Helper function to open a flow file with a nice extension.
 */

static FILE*
snmp_flow_open_stream(snmp_flow_t *flow, snmp_write_t *out, const char *mode)
{
#define MAX_FILENAME_SIZE 4096
    char filename[MAX_FILENAME_SIZE];
    FILE *stream;

    snprintf(filename, MAX_FILENAME_SIZE, "%s%s%s%s%s.%s",
	     out->path ? out->path : "",
	     out->path ? "/" : "",
	     out->prefix ? out->prefix : "",
	     out->prefix ? "-" : "",
	     flow->name,
	     out->ext ? out->ext : "");
    stream = fopen(filename, mode);
    if (! stream) {
	fprintf(stderr, "%s: failed to open flow file %s: %s\n",
		progname, filename, strerror(errno));
    }
    return stream;
}

/*
 * Helper function to close a flow file stream. Any stream errors that
 * might have occured are reported to stderr.
 */

static void
snmp_flow_close_stream(snmp_flow_t *flow)
{
    if (flow && flow->stream) {
	if (fflush(flow->stream) || ferror(flow->stream)) {
	    fprintf(stderr, "%s: error on flow stream %s: %s\n",
		    progname, flow->name, strerror(errno));
	}
	fclose(flow->stream);
	flow->stream = NULL;
    }
}

/*
 * Below are the interface functions as defined in snmp.h, namely the
 * initializing function, the per packet write functions, and the
 * finalizing function.
 */

void
snmp_flow_init(snmp_write_t *out)
{
    /* nothing to be done here yet */
}

/*
 * We keep an LRU cache of open flows to reduce the number of open()
 * close() system calls.
 */

static snmp_flow_t **open_flow_cache = NULL;
static int open_flow_cache_size = 0;
static int cnt = 0;

static void
open_flow_cache_init()
{
    struct rlimit rl;

    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {
	fprintf(stderr,
		"%s: getrlimit() failed: unable to allocate open flow cache\n",
		progname);
	exit(1);
    }
    
    if (rl.rlim_max == RLIM_INFINITY) {
	open_flow_cache_size = 1024;		/* pretend to be like Linux */
    } else if (rl.rlim_max > 8) {		/* arbitrary safety margin */
	open_flow_cache_size = rl.rlim_max - 8;
    } else {
	fprintf(stderr, "%s: not enough open file descriptors left\n",
		progname);
	exit(1);
    }

    open_flow_cache = xmalloc(sizeof(snmp_flow_t*) * open_flow_cache_size);
}

#if 0
static void
open_flow_cache_print()
{
    int i;

    for (i = 0; i < open_flow_cache_size; i++) {
	fprintf(stderr, "%3d: %s\n", i,
		open_flow_cache[i] ? open_flow_cache[i]->name : "");
    }
}
#endif

static void
open_flow_cache_add(snmp_flow_t *flow)
{
    int i, j;
    snmp_flow_t *tmp;

    for (i = 0; i < open_flow_cache_size; i++) {
	if (open_flow_cache[i] == flow) {
	    break;
	}
	if (!open_flow_cache[i]) {
	    i = open_flow_cache_size;
	    break;
	}
    }

    /* The current flow is on the top - don't bother any further... */

    if (i == 0) {
	if (! open_flow_cache[0]) {
	    open_flow_cache[0] = flow;
	}
	return;
    }

    /* Flow not found in the cache, so close the last flow and assign
       the new flow to it... */
    
    if (i == open_flow_cache_size) {
	i--;
	if (open_flow_cache[i]) {
	    snmp_flow_close_stream(open_flow_cache[i]);
	}
	open_flow_cache[i] = flow;
    }

    /* Move the flow to the top... */

    tmp = open_flow_cache[i];
    for (j = i; j > 0; j--) {
	open_flow_cache[j] = open_flow_cache[j-1];
    }
    open_flow_cache[0] = tmp;
}

void
snmp_flow_write(snmp_write_t *out, snmp_packet_t *pkt)
{
    snmp_flow_t *flow;

    if (cnt == 0) {
	open_flow_cache_init();
    }

    cnt++;

    /* the following constants should (a) have reasonable values and
     * (b) be configurable */

    if (! (cnt % 1024)) {
	snmp_cache_list = snmp_cache_expire(snmp_cache_list,
					    pkt->time_sec.value - 300,
					    pkt->time_usec.value);
    }
    
    flow = snmp_flow_find(pkt);
    if (flow && flow->name) {
	if (! flow->stream) {
	    flow->stream = snmp_flow_open_stream(flow, out,
						 (flow->cnt == 0) ? "w" : "a");
	}
	if (flow->stream) {
	    if (flow->cnt == 0 && out->write_new) {
		out->write_new(flow->stream);
	    }
	    if (out->write_pkt) {
		out->write_pkt(flow->stream, pkt);
	    }
	    flow->cnt++;
	    if (pkt->snmp.scoped_pdu.pdu.type != SNMP_PDU_RESPONSE
		&& pkt->snmp.scoped_pdu.pdu.type != SNMP_PDU_TRAP1
		&& pkt->snmp.scoped_pdu.pdu.type != SNMP_PDU_TRAP2
		&& pkt->snmp.scoped_pdu.pdu.type != SNMP_PDU_RESPONSE) {
		snmp_cache_list = snmp_cache_add(snmp_cache_list, pkt);
	    }
	    open_flow_cache_add(flow);
	    return;
	}
    }

    /*
     * xxx shall we cache these packets since the request might still
     * be coming? xxx
     */

    if (out->stream && out->write_pkt) {
	out->write_pkt(out->stream, pkt);
    }
    snmp_cache_list = snmp_cache_add(snmp_cache_list, pkt);
}

void
snmp_flow_done(snmp_write_t *out)
{
    snmp_flow_t *p, *q;

    for (p = flow_list; p; ) {
	if (p->name) {
	    if (! p->stream) {
		p->stream = snmp_flow_open_stream(p, out, "a");
	    }
	    if (p->stream) {
		if (out->write_end) {
		    out->write_end(p->stream);
		}
		snmp_flow_close_stream(p);
	    }
	    free(p->name);
	}
	q = p->next;
	free(p);
	p = q;
    }

    if (open_flow_cache) {
	free(open_flow_cache);
	open_flow_cache = NULL;
	open_flow_cache_size = 0;
	cnt = 0;
    }
}
