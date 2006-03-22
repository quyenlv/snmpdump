/*
 * csv-write.c --
 *
 * Serialize the most important information about an SNMP packet into
 * as comma separated values (CSV). The format is specified in the
 * measure.txt documentation.
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
csv_write_ipaddr(FILE *stream, snmp_ipaddr_t *addr)
{
    char buffer[INET_ADDRSTRLEN];

    if (addr->attr.flags & SNMP_FLAG_VALUE
	&& inet_ntop(AF_INET, &addr->value, buffer, sizeof(buffer))) {
	fprintf(stream, "%c%s", sep, buffer);
    } else {
	fprintf(stream, "%c", sep);
    }
}


static void
csv_write_ip6addr(FILE *stream, snmp_ip6addr_t *addr)
{
    char buffer[INET6_ADDRSTRLEN];

    if (addr->attr.flags & SNMP_FLAG_VALUE
	&& inet_ntop(AF_INET6, &addr->value, buffer, sizeof(buffer))) {
	fprintf(stream, "%c%s", sep, buffer);
    } else {
	fprintf(stream, "%c", sep);
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
csv_write_uint32(FILE *stream, snmp_uint32_t *val)
{
    if (val->attr.flags & SNMP_FLAG_VALUE) {
	fprintf(stream, "%c%"PRIu32, sep, val->value);
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

    fprintf(stream, "%u.%06u", pkt->time_sec.value, pkt->time_usec.value);

    if (pkt->src_addr.attr.flags & SNMP_FLAG_VALUE) {
	csv_write_ipaddr(stream, &pkt->src_addr);
    } else {
	csv_write_ip6addr(stream, &pkt->src_addr6);
    }
    csv_write_uint32(stream, &pkt->src_port);
    if (pkt->dst_addr.attr.flags & SNMP_FLAG_VALUE) {
	csv_write_ipaddr(stream, &pkt->dst_addr);
    } else {
	csv_write_ip6addr(stream, &pkt->dst_addr6);
    }
    csv_write_uint32(stream, &pkt->dst_port);

    if (pkt->snmp.attr.flags & SNMP_FLAG_BLEN) {
	fprintf(stream, "%c%d", sep, pkt->snmp.attr.blen);
    } else {
	fprintf(stream, "%c", sep);
    }

    if (pkt->snmp.attr.flags & SNMP_FLAG_VALUE) {
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
    }

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
