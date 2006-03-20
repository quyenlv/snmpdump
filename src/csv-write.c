/*
 * csv-write.c --
 *
 * Serialize the most important information about an SNMP packet into
 * as comma separated values (CSV). Every output line contains the
 * following fields:
 *
 *   a) time-stamp in seconds.microseconds format
 *   b) src address
 *   c) src port
 *   d) dst address
 *   e) dst port
 *   f) snmp message size
 *   g) snmp message version
 *   h) protocol operation (get/next/bulk/set/trap/inform/response/report)
 *   i) request ID
 *   j) error status
 *   k) error index
 *   l) number of varbinds
 *   *) list of object names in dotted notation
 *
 * Copyright (c) 2006 Juergen Schoenwaelder
 *
 * $Id$
 */

#include "snmp.h"

#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static const char sep = ',';

static void
csv_write_addr(FILE *stream, struct sockaddr *addr,
	       int show_addr, int show_port)
{
    struct sockaddr_in *sinv4;
    
    switch (addr->sa_family) {
    case AF_INET:
	sinv4 = (struct sockaddr_in *) addr;
	if (show_addr) {
	    fprintf(stream, "%c%s", sep, inet_ntoa(sinv4->sin_addr));
	} else {
	    fprintf(stream, "%c", sep);
	}
	if (show_port) {
	    fprintf(stream, "%c%d", sep, sinv4->sin_port);
	} else {
	    fprintf(stream, "%c", sep);
	}
	break;
    default:
	break;
    }
}

static void
csv_write_int32(FILE *stream, snmp_int32_t *val)
{
    if (val->attr.flags & SNMP_FLAG_VALUE) {
	fprintf(stream, "%c%"PRId32, sep, val->value);
    } else {
	fprintf(stream, "%c", sep);
    }
}

static void
csv_write_type(FILE *stream, int type, snmp_attr_t  *attr)
{
    const char *name = NULL;
    
    if (attr->flags & SNMP_FLAG_VALUE) {
	switch (type) {
	case SNMP_PDU_GET:
	    name = "get-request";
	    break;
	case SNMP_PDU_GETNEXT:
	    name = "get-next-request";
	    break;
	case SNMP_PDU_GETBULK:
	    name = "get-bulk-request";
	    break;
	case SNMP_PDU_SET:
	    name = "set-request";
	    break;
	case SNMP_PDU_RESPONSE:
	    name = "response";
	    break;
	case SNMP_PDU_TRAP1:
	    name = "trap";
	    break;
	case SNMP_PDU_TRAP2:
	    name = "trap2";
	    break;
	case SNMP_PDU_INFORM:
	    name = "inform";
	    break;
	case SNMP_PDU_REPORT:
	    name = "report";
	    break;
	}
	fprintf(stream, "%c%s", sep, name ? name : "");
    } else {
	fprintf(stream, "%c", sep);
    }
}

static void
csv_write_varbind_count(FILE *stream, snmp_varbind_t *varbind)
{
    int c;

    for (c = 0; varbind; varbind = varbind->next, c++) ;

    fprintf(stream, "%c%d", sep, c);
}

static void
csv_write_varbind_names(FILE *stream, snmp_varbind_t *varbind)
{
    int i;
    snmp_oid_t *name;

    for (; varbind; varbind = varbind->next) {
	name = &varbind->name;
	if (name->attr.flags & SNMP_FLAG_VALUE) {
	    for (i = 0; i < name->len; i++) {
		fprintf(stream, "%c%"PRIu32, (i == 0) ? sep : '.', name->value[i]);
	    }
	} else {
	    fprintf(stream, "%c", sep);
	}
    }
}

void
snmp_csv_write_stream(FILE *stream, snmp_packet_t *pkt)
{
    if (! pkt) return;

    fprintf(stream, "%u.%06u", pkt->time.tv_sec, pkt->time.tv_usec);

    csv_write_addr(stream, (struct sockaddr *) &pkt->src,
		   pkt->attr.flags & SNMP_FLAG_SADDR,
		   pkt->attr.flags & SNMP_FLAG_SPORT);
    csv_write_addr(stream, (struct sockaddr *) &pkt->dst,
		   pkt->attr.flags & SNMP_FLAG_DADDR,
		   pkt->attr.flags & SNMP_FLAG_DPORT);
    
    if (pkt->snmp.attr.flags & SNMP_FLAG_BLEN) {
	fprintf(stream, "%c%d", sep, pkt->snmp.attr.blen);
    } else {
	fprintf(stream, "%c", sep);
    }

    csv_write_int32(stream, &pkt->snmp.version);

    csv_write_type(stream, pkt->snmp.scoped_pdu.pdu.type,
		   &pkt->snmp.scoped_pdu.pdu.attr);

    csv_write_int32(stream, &pkt->snmp.scoped_pdu.pdu.req_id);

    csv_write_int32(stream, &pkt->snmp.scoped_pdu.pdu.err_status);
    
    csv_write_int32(stream, &pkt->snmp.scoped_pdu.pdu.err_index);

    csv_write_varbind_count(stream,
			    pkt->snmp.scoped_pdu.pdu.varbindings.varbind);

    csv_write_varbind_names(stream,
			    pkt->snmp.scoped_pdu.pdu.varbindings.varbind);

    fprintf(stream, "\n");
}

void
snmp_csv_write_stream_begin(FILE *stream)
{
    /* this is at the moment an empty entry point */
}

void
snmp_csv_write_stream_end(FILE *stream)
{
    /* this is at the moment an empty entry point */
}
