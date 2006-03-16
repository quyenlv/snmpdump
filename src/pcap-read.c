/*
 * pcap-read.c --
 *
 * A utility to convert pcap capture files containing SNMP messages
 * into snmp trace files. To create these pcap files, you can use:
 *
 *    tcpdump -i <interface> -s 0 -w <filename> udp and port 161 or port 162
 *
 * To convert the SNMP messages to XML, use this command:
 *
 *    snmpdump <filename>
 *
 * This implementation generates XML output directly rather than using
 * and XML writer API in order to be fast and memory efficient.
 *
 * (c) 2004-2005 Juergen Schoenwaelder <j.schoenwaelder@iu-bremen.de>
 *
 * This code is derived from the print-snmp.c module shipped as part
 * of tcpdump. The copyrigths notes of this tcpdump module say:
 *
 * Copyright (c) 1990, 1991, 1993, 1994, 1995, 1996, 1997
 *     John Robert LoVerso. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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
 *
 * Support for SNMPv2c/SNMPv3 and the ability to link the module against
 * the libsmi was added by J. Schoenwaelder, Copyright (c) 1999.
 */

#define _GNU_SOURCE

#define HACK_AROUND_LIBNET_API_CHANGES

#ifdef HACK_AROUND_LIBNET_API_CHANGES
int libnet_build_ip() { return libnet_build_ipv4(); }
int libnet_write_ip() { return libnet_write_raw_ipv4(); }
int libnet_open_raw_sock() { return libnet_open_raw4(); }
#endif

#include "config.h"

#include "snmp.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <inttypes.h>
#include <assert.h>

#include <sys/types.h>
#include <regex.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <pcap.h>

#include <nids.h>

#if 0
/* needed to work around a bug in libnids */
extern struct pcap_pkthdr *nids_last_pcap_header;
#endif

/* libnids does not allow to pass user data - this is not thread safe */
static snmp_callback user_callback = NULL;
static void *user_data = NULL;

static int iflag = 0;

#define timediff2(t1,t2)  (((t2).tv_sec - (t1).tv_sec) * 1000 \
        + ((t2).tv_usec - (t1).tv_usec) / 1000)
#define time_diff(t1,t2)  (timediff2(t1,t2) <= 0 ? (- timediff2(t1,t2)) \
                           : timediff2(t1,t2))

static regex_t _clr_regex, _del_regex;
static regex_t *clr_regex = NULL, *del_regex = NULL;

/* static int in_delete = 0; */
/* static int in_clear = 0; */


/*
 * Start an xml element with the given indentation and name and add
 * the blen and vlan attributes.
 */

static void
xml_elem_start(const int indent, const char *name,
	       const int blen, const int vlen)
{
    printf("%*s<%s blen=\"%d\" vlen=\"%d\">%s", iflag ? indent : 0, "",
	   name, blen, vlen, iflag ? "\n" : "");
}

/*
 * Close an xml element with the given indentation and name.
 */

static void
xml_elem_end(const int indent, const char *name)
{
    printf("%*s</%s>%s", iflag ? indent : 0, "", name, iflag ? "\n" : "");
}

/*
 * Create a leaf xml element the given indentation and name and add
 * the blen and vlan attributes. The format is determined using
 * printf-style arguments.
 */

static void
xml_leaf(const int indent, const char *name,
	 const int blen, const int vlen, const char *format, ...)
{
    va_list args;
    
    if (format) {
	printf("%*s<%s blen=\"%d\" vlen=\"%d\">",
	       iflag ? indent : 0, "", name, blen, vlen);
	va_start(args, format);
	vprintf(format, args);
	va_end(args);
	printf("</%s>%s", name, iflag ? "\n" : "");
    } else {
	printf("%*s<%s blen=\"%d\" vlen=\"%d\"/>%s",
	       iflag ? indent : 0, "", name, blen, vlen, iflag ? "\n" : "");
    }
}

/*
 * Convert octet string values into something useful.
 */

static char*
hexify(const int len, const u_char *str)
{
	static size_t size = 0;
	static char *buffer = NULL;
	int i;

	if (len < 0) {
		return NULL;
	}

	if (size < 2*len+1) {
		size = 2*len+1;
		buffer = realloc(buffer, size);
		if (! buffer) {
			size = 0;
			return NULL;
		}
	}
	
	for (i = 0; i < len; i++) {
		snprintf(buffer+2*i, size-2*i, "%.2x", str[i]);
	}
	return buffer;
}

/*
 * generic-trap values in the SNMP Trap-PDU
 */
const char *GenericTrap[] = {
	"coldStart",
	"warmStart",
	"linkDown",
	"linkUp",
	"authenticationFailure",
	"egpNeighborLoss",
	"enterpriseSpecific"
#define GT_ENTERPRISE 6
};
#define DECODE_GenericTrap(t) \
	( t >= 0 && (size_t)t < sizeof(GenericTrap)/sizeof(GenericTrap[0]) \
		? GenericTrap[t] \
		: (snprintf(buf, sizeof(buf), "gt=%d", t), buf))


/*
 * Universal ASN.1 types
 * (we only care about the tag values for those allowed in the Internet SMI)
 */
const char *Universal[] = {
	"U-0",
	"Boolean",
	"Integer",
#define INTEGER 2
	"Bitstring",
	"String",
#define STRING 4
	"Null",
#define ASN_NULL 5
	"ObjID",
#define OBJECTID 6
	"ObjectDes",
	"U-8","U-9","U-10","U-11",	/* 8-11 */
	"U-12","U-13","U-14","U-15",	/* 12-15 */
	"Sequence",
#define SEQUENCE 16
	"Set"
};

/*
 * Application-wide ASN.1 types from the Internet SMI and their tags
 */
const char *Application[] = {
	"IpAddress",
#define IPADDR 0
	"Counter",
#define COUNTER 1
	"Gauge",
#define GAUGE 2
	"TimeTicks",
#define TIMETICKS 3
	"Opaque",
#define OPAQUE 4
	"C-5",
	"Counter64"
#define COUNTER64 6
};

/*
 * Context-specific ASN.1 types for the SNMP PDUs and their tags
 */
const char *Context[] = {
	"get-request",
#define GETREQ 0
	"get-next-request",
#define GETNEXTREQ 1
	"response",
#define GETRESP 2
	"set-request",
#define SETREQ 3
	"trap",
#define TRAP 4
	"get-bulk-request",
#define GETBULKREQ 5
	"inform",
#define INFORMREQ 6
	"trap-v2",
#define V2TRAP 7
	"report"
#define REPORT 8
};

#define NOTIFY_CLASS(x)	    (x == TRAP || x == V2TRAP || x == INFORMREQ)
#define READ_CLASS(x)       (x == GETREQ || x == GETNEXTREQ || x == GETBULKREQ)
#define WRITE_CLASS(x)	    (x == SETREQ)
#define RESPONSE_CLASS(x)   (x == GETRESP)
#define INTERNAL_CLASS(x)   (x == REPORT)

/*
 * Context-specific ASN.1 types for the SNMP Exceptions and their tags
 */
const char *Exceptions[] = {
	"noSuchObject",
#define NOSUCHOBJECT 0
	"noSuchInstance",
#define NOSUCHINSTANCE 1
	"endOfMibView",
#define ENDOFMIBVIEW 2
};

/*
 * Private ASN.1 types
 * The Internet SMI does not specify any
 */
const char *Private[] = {
	"P-0"
};

/*
 * ASN.1 type class table
 * Ties together the preceding Universal, Application, Context, and Private
 * type definitions.
 */
#define defineCLASS(x) { "x", x, sizeof(x)/sizeof(x[0]) } /* not ANSI-C */
struct {
	const char	*name;
	const char	**Id;
	    int	numIDs;
    } Class[] = {
	defineCLASS(Universal),
#define	UNIVERSAL	0
	defineCLASS(Application),
#define	APPLICATION	1
	defineCLASS(Context),
#define	CONTEXT		2
	defineCLASS(Private),
#define	PRIVATE		3
	defineCLASS(Exceptions),
#define EXCEPTIONS	4
};

/*
 * defined forms for ASN.1 types
 */
const char *Form[] = {
	"Primitive",
#define PRIMITIVE	0
	"Constructed",
#define CONSTRUCTED	1
};

/*
 * This is used in the OID print routine to walk down the object tree
 * rooted at `mibroot'.
 */
#define OBJ_PRINT(o, suppressdot) \
{ \
		printf(suppressdot?"%u":".%u", (o)); \
}

/*
 * This is the definition for the Any-Data-Type storage used purely for
 * temporary internal representation while decoding an ASN.1 data stream.
 */
struct be {
	uint32_t asnlen;
	union {
		caddr_t raw;
		int32_t integer;
		uint32_t uns;
		const u_char *str;
		uint64_t uns64;
	} data;
	uint16_t id;
	u_char form, class;		/* tag info */
	u_char type;
#define BE_ANY		255
#define BE_NONE		0
#define BE_NULL		1
#define BE_OCTET	2
#define BE_OID		3
#define BE_INT		4
#define BE_UNS		5
#define BE_STR		6
#define BE_SEQ		7
#define BE_INETADDR	8
#define BE_PDU		9
#define BE_UNS64	10
#define BE_NOSUCHOBJECT	128
#define BE_NOSUCHINST	129
#define BE_ENDOFMIBVIEW	130
};

struct {
	int id;
	const char *name;
} Types[] = {
	{ BE_ANY,		"any" },
	{ BE_NONE,		"none" },
	{ BE_NULL,		"null" },
	{ BE_OCTET,		"opaque" },
	{ BE_OID,		"object-identifier" },
	{ BE_INT,		"integer32" },
	{ BE_UNS,		"unsigned32" },
	{ BE_STR,		"octet-string" },
	{ BE_SEQ,		"sequence" },
	{ BE_INETADDR,		"ipaddress" },
	{ BE_PDU,		"pdu" },
	{ BE_UNS64,		"unsigned64" },
	{ BE_NOSUCHOBJECT,	"no-such-object" },
	{ BE_NOSUCHINST,	"no-such-instance" },
	{ BE_ENDOFMIBVIEW,	"end-of-mib-view" },
	{	0,		NULL }
};


/*
 * SNMP versions recognized by this module
 */

const char *SnmpVersion[] = {
	"SNMPv1",
#define SNMP_VERSION_1	0
	"SNMPv2c",
#define SNMP_VERSION_2	1
	"SNMPv2u",
#define SNMP_VERSION_2U	2
	"SNMPv3"
#define SNMP_VERSION_3	3
};


static int truncated;


/*
 * constants for ASN.1 decoding
 */
#define OIDMUX 40
#define ASNLEN_INETADDR 4
#define ASN_SHIFT7 7
#define ASN_SHIFT8 8
#define ASN_BIT8 0x80
#define ASN_LONGLEN 0x80

#define ASN_ID_BITS 0x1f
#define ASN_FORM_BITS 0x20
#define ASN_FORM_SHIFT 5
#define ASN_CLASS_BITS 0xc0
#define ASN_CLASS_SHIFT 6

#define ASN_ID_EXT 0x1f		/* extension ID in tag field */

/*
 * truncated==1 means the packet was complete, but we don't have all of
 * it to decode.
 */
static int truncated;
#define ifNotTruncated if (truncated) fputs("[|snmp]", stdout); else

/*
 * This decodes the next ASN.1 object in the stream pointed to by "p"
 * (and of real-length "len") and stores the intermediate data in the
 * provided BE object.
 *
 * This returns -l if it fails (i.e., the ASN.1 stream is not valid).
 * O/w, this returns the number of bytes parsed from "p".
 */
static int
asn1_parse(register const u_char *p, u_int len, struct be *elem)
{
	u_char form, class, id;
	int i, hdr;

	elem->asnlen = 0;
	elem->type = BE_ANY;
	if (len < 1) {
		ifNotTruncated fputs("[nothing to parse]", stdout);
		return -1;
	}

	/*
	 * it would be nice to use a bit field, but you can't depend on them.
	 *  +---+---+---+---+---+---+---+---+
	 *  + class |frm|        id         |
	 *  +---+---+---+---+---+---+---+---+
	 *    7   6   5   4   3   2   1   0
	 */
	id = *p & ASN_ID_BITS;		/* lower 5 bits, range 00-1f */
#ifdef notdef
	form = (*p & 0xe0) >> 5;	/* move upper 3 bits to lower 3 */
	class = form >> 1;		/* bits 7&6 -> bits 1&0, range 0-3 */
	form &= 0x1;			/* bit 5 -> bit 0, range 0-1 */
#else
	form = (u_char)(*p & ASN_FORM_BITS) >> ASN_FORM_SHIFT;
	class = (u_char)(*p & ASN_CLASS_BITS) >> ASN_CLASS_SHIFT;
#endif
	elem->form = form;
	elem->class = class;
	elem->id = id;
	p++; len--; hdr = 1;
	/* extended tag field */
	if (id == ASN_ID_EXT) {
		for (id = 0; *p & ASN_BIT8 && len > 0; len--, hdr++, p++)
			id = (id << 7) | (*p & ~ASN_BIT8);
		if (len == 0 && *p & ASN_BIT8) {
			ifNotTruncated fputs("[Xtagfield?]", stdout);
			return -1;
		}
		elem->id = id = (id << 7) | *p;
		--len;
		++hdr;
		++p;
	}
	if (len < 1) {
		ifNotTruncated fputs("[no asnlen]", stdout);
		return -1;
	}
	elem->asnlen = *p;
	p++; len--; hdr++;
	if (elem->asnlen & ASN_BIT8) {
		uint32_t noct = elem->asnlen % ASN_BIT8;
		elem->asnlen = 0;
		if (len < noct) {
			ifNotTruncated printf("[asnlen? %d<%d]", len, noct);
			return -1;
		}
		for (; noct-- > 0; len--, hdr++)
			elem->asnlen = (elem->asnlen << ASN_SHIFT8) | *p++;
	}
	if (len < elem->asnlen) {
		if (!truncated) {
			printf("[len%d<asnlen%u]", len, elem->asnlen);
			return -1;
		}
		/* maybe should check at least 4? */
		elem->asnlen = len;
	}
	if (form >= sizeof(Form)/sizeof(Form[0])) {
		ifNotTruncated printf("[form?%d]", form);
		return -1;
	}
	if (class >= sizeof(Class)/sizeof(Class[0])) {
		ifNotTruncated printf("[class?%c/%d]", *Form[form], class);
		return -1;
	}
	if ((int)id >= Class[class].numIDs) {
		ifNotTruncated printf("[id?%c/%s/%d]", *Form[form],
			Class[class].name, id);
		return -1;
	}

	switch (form) {
	case PRIMITIVE:
		switch (class) {
		case UNIVERSAL:
			switch (id) {
			case STRING:
				elem->type = BE_STR;
				elem->data.str = p;
				break;

			case INTEGER: {
				register int32_t data;
				elem->type = BE_INT;
				data = 0;

				if (*p & ASN_BIT8)	/* negative */
					data = -1;
				for (i = elem->asnlen; i-- > 0; p++)
					data = (data << ASN_SHIFT8) | *p;
				elem->data.integer = data;
				break;
			}

			case OBJECTID:
				elem->type = BE_OID;
				elem->data.raw = (caddr_t)p;
				break;

			case ASN_NULL:
				elem->type = BE_NULL;
				elem->data.raw = NULL;
				break;

			default:
				elem->type = BE_OCTET;
				elem->data.raw = (caddr_t)p;
				printf("[P/U/%s]",
					Class[class].Id[id]);
				break;
			}
			break;

		case APPLICATION:
			switch (id) {
			case IPADDR:
				elem->type = BE_INETADDR;
				elem->data.raw = (caddr_t)p;
				break;

			case COUNTER:
			case GAUGE:
			case TIMETICKS: {
				register uint32_t data;
				elem->type = BE_UNS;
				data = 0;
				for (i = elem->asnlen; i-- > 0; p++)
					data = (data << 8) + *p;
				elem->data.uns = data;
				break;
			}

			case COUNTER64: {
				register uint32_t data;
			        elem->type = BE_UNS64;
				data = 0;
				for (i = elem->asnlen; i-- > 0; p++) {
					data = (data << 8) + *p;
				}
				elem->data.uns64 = data;
				break;
			}

			default:
				elem->type = BE_OCTET;
				elem->data.raw = (caddr_t)p;
				printf("[P/A/%s]",
					Class[class].Id[id]);
				break;
			}
			break;

		case CONTEXT:
			switch (id) {
			case NOSUCHOBJECT:
				elem->type = BE_NOSUCHOBJECT;
				elem->data.raw = NULL;
				break;

			case NOSUCHINSTANCE:
				elem->type = BE_NOSUCHINST;
				elem->data.raw = NULL;
				break;

			case ENDOFMIBVIEW:
				elem->type = BE_ENDOFMIBVIEW;
				elem->data.raw = NULL;
				break;
			}
			break;

		default:
			elem->type = BE_OCTET;
			elem->data.raw = (caddr_t)p;
			printf("[P/%s/%s]",
				Class[class].name, Class[class].Id[id]);
			break;
		}
		break;

	case CONSTRUCTED:
		switch (class) {
		case UNIVERSAL:
			switch (id) {
			case SEQUENCE:
				elem->type = BE_SEQ;
				elem->data.raw = (caddr_t)p;
				break;

			default:
				elem->type = BE_OCTET;
				elem->data.raw = (caddr_t)p;
				printf("C/U/%s", Class[class].Id[id]);
				break;
			}
			break;

		case CONTEXT:
			elem->type = BE_PDU;
			elem->data.raw = (caddr_t)p;
			break;

		default:
			elem->type = BE_OCTET;
			elem->data.raw = (caddr_t)p;
			printf("C/%s/%s",
				Class[class].name, Class[class].Id[id]);
			break;
		}
		break;
	}
	p += elem->asnlen;
	len -= elem->asnlen;
	return elem->asnlen + hdr;
}

/*
 * Display the ASN.1 object represented by the BE object.
 * This used to be an integral part of asn1_parse() before the intermediate
 * BE form was added.
 */
static const char*
asn1_print(struct be *elem)
{
	static char buffer[1024];
	char numbuf[20];
	u_char *p = (u_char *)elem->data.raw;
	uint32_t asnlen = elem->asnlen;

	buffer[0] = 0;

	switch (elem->type) {

	case BE_OCTET:
		return hexify(asnlen, p);

	case BE_NULL:
		return buffer;

	case BE_OID: {
	int o = 0, first = -1, i = asnlen;

		for (; i-- > 0; p++) {
			o = (o << ASN_SHIFT7) + (*p & ~ASN_BIT8);
			if (*p & ASN_LONGLEN)
			        continue;

			/*
			 * first subitem encodes two items with 1st*OIDMUX+2nd
			 * (see X.690:1997 clause 8.19 for the details)
			 */
			if (first < 0) {
			        int s;
				first = 0;
				s = o / OIDMUX;
				if (s > 2) s = 2;
				snprintf(buffer, sizeof(buffer), "%d", s);
				/* OBJ_PRINT(s, first); */
				o -= s * OIDMUX;
			}
			snprintf(numbuf, sizeof(numbuf), ".%d", o);
			strcat(buffer, numbuf);
			/* OBJ_PRINT(o, first); */
			if (--first < 0)
				first = 0;
			o = 0;
		}
		return buffer;
	}

	case BE_INT:
		sprintf(buffer, "%"PRIi32, elem->data.integer);
		return buffer;

	case BE_UNS:
		sprintf(buffer, "%"PRIu32, elem->data.uns);
		return buffer;

	case BE_UNS64:
		sprintf(buffer, "%"PRIu64, elem->data.uns64);
		return buffer;

	case BE_STR: {
#if 0
		register int printable = 1, first = 1;
		const u_char *p = elem->data.str;
		for (i = asnlen; printable && i-- > 0; p++)
			printable = isprint(*p) || isspace(*p);
		p = elem->data.str;
		if (printable) {
			snprintf(buffer, sizeof(buffer), "%.*s",
				 asnlen, elem->data.str);
			return buffer;
		} else
			for (i = asnlen; i-- > 0; p++) {
				printf(first ? "(fix me)%.2x" : "_%.2x", *p);
				first = 0;
			}

#else
		return hexify(asnlen, p);
#endif
		break;
	}

	case BE_SEQ:
		return NULL;

	case BE_INETADDR:
		if (asnlen != ASNLEN_INETADDR)
			fprintf(stderr, "[inetaddr len!=%d]\n",
				ASNLEN_INETADDR);
		sprintf(buffer, "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
		return buffer;

	case BE_NOSUCHOBJECT:
	case BE_NOSUCHINST:
	case BE_ENDOFMIBVIEW:
	        return Class[EXCEPTIONS].Id[elem->id];

	case BE_PDU:
		return Class[CONTEXT].Id[elem->id];

	case BE_ANY:
		fputs("[BE_ANY!?]\n", stderr);
		return NULL;

	default:
		fputs("[be!?]\n", stderr);
		return NULL;
	}
}

/*
 * Helper to fill an snmp_int32_t with values.
 */

static void
set_int32(snmp_int32_t *v, int count, struct be *elem)
{
    v->value = elem->data.integer;
    v->attr.blen = count;
    v->attr.vlen = elem->asnlen;
    v->attr.flags = SNMP_FLAG_VALUE | SNMP_FLAG_BLEN | SNMP_FLAG_VLEN;
}

/*
 * Helper to fill an snmp_uint32_t with values.
 */

static void
set_uint32(snmp_uint32_t *v, int count, struct be *elem)
{
    v->value = elem->data.uns;
    v->attr.blen = count;
    v->attr.vlen = elem->asnlen;
    v->attr.flags = SNMP_FLAG_VALUE | SNMP_FLAG_BLEN | SNMP_FLAG_VLEN;
}

/*
 * Helper to fill an snmp_octs_t with values.
 */

static void
set_octs(snmp_octs_t *v, int count, struct be *elem)
{
    v->value = (unsigned char *) elem->data.raw;
    v->len = elem->asnlen;
    v->attr.blen = count;
    v->attr.vlen = elem->asnlen;
    v->attr.flags = SNMP_FLAG_VALUE | SNMP_FLAG_BLEN | SNMP_FLAG_VLEN;
}

/*
 * Helper to fill an snmp_oid_t with values.
 */

static void
set_oid(snmp_oid_t *v, int count, struct be *elem)
{
    v->value = NULL;		/* XXX fix me XXX */
    v->len = 0;
    v->attr.blen = count;
    v->attr.vlen = elem->asnlen;
    v->attr.flags = SNMP_FLAG_VALUE | SNMP_FLAG_BLEN | SNMP_FLAG_VLEN;
}

/*
 * Helper to fill an snmp_ipaddr_t with values.
 */

static void
set_ipaddr(snmp_ipaddr_t *v, int count, struct be *elem)
{
    v->value = 0;		/* XXX fix me XXX */
    v->attr.blen = count;
    v->attr.vlen = elem->asnlen;
    v->attr.flags = SNMP_FLAG_VALUE | SNMP_FLAG_BLEN | SNMP_FLAG_VLEN;
}



/*
 * Decode an SNMP varbind list.
 */

static void
varbind_print(u_char pduid, const u_char *np, u_int length, snmp_packet_t *pkt)
{
	const char *val;
	
	struct be elem;
	int i, count = 0, ind;

	/* Sequence of varBind */
	if ((count = asn1_parse(np, length, &elem)) < 0)
		return;
	if (elem.type != BE_SEQ) {
		fputs("[!SEQ of varbind]\n", stderr);
		return;
	}
	if ((u_int)count < length)
		fprintf(stderr, "[%d extra after SEQ of varbind]\n",
			length - count);

	pkt->msg.scoped_pdu.pdu.varbindings.attr.blen
		= length;
	pkt->msg.scoped_pdu.pdu.varbindings.attr.vlen
		= elem.asnlen;
	pkt->msg.scoped_pdu.pdu.varbindings.attr.flags
		= SNMP_FLAG_VALUE | SNMP_FLAG_BLEN | SNMP_FLAG_VLEN;

	length = elem.asnlen;
	np = (u_char *)elem.data.raw;

	for (ind = 1; length > 0; ind++) {
		const u_char *vbend;
		u_int vblength;
		snmp_varbind_t *vb;

		vb = (snmp_varbind_t *) malloc(sizeof(snmp_varbind_t));
		if (! vb) {
			abort();
		}
		memset(vb, 0, sizeof(snmp_varbind_t));

		/* Sequence */
		if ((count = asn1_parse(np, length, &elem)) < 0)
			return;
		if (elem.type != BE_SEQ) {
			fputs("[!varbind]\n", stderr);
			return;
		}

		vb->attr.blen = count;
		vb->attr.vlen = elem.asnlen;
		vb->attr.flags
			= SNMP_FLAG_VALUE | SNMP_FLAG_BLEN | SNMP_FLAG_VLEN;
		
		vbend = np + count;
		vblength = length - count;
		/* descend */
		length = elem.asnlen;
		np = (u_char *)elem.data.raw;

		/* objName (OID) */
		if ((count = asn1_parse(np, length, &elem)) < 0)
			return;
		if (elem.type != BE_OID) {
			fputs("[objName!=OID]\n", stderr);
			return;
		}

		val = asn1_print(&elem);
		xml_leaf(indent+4, "name", count, elem.asnlen, "%s", val);
		length -= count;
		np += count;

		/* objVal (ANY) */
		if ((count = asn1_parse(np, length, &elem)) < 0)
			return;

		for (i = 0; Types[i].name; i++) {
			if (Types[i].id == elem.type) break;
		}

		val = asn1_print(&elem);
		if (Types[i].id == BE_NOSUCHOBJECT
		    || Types[i].id == BE_NOSUCHINST
		    || Types[i].id == BE_ENDOFMIBVIEW) {
			xml_leaf(indent+4, Types[i].name ? Types[i].name : "value",
				 count, elem.asnlen, NULL);
		} else {
			xml_leaf(indent+4, Types[i].name ? Types[i].name : "value",
				 count, elem.asnlen, "%s", val);
		}
		xml_elem_end(indent+2, "varbind");
		
		length = vblength;
		np = vbend;
	}
}

/*
 * Decode "generic" SNMP PDUs such asGetRequest, GetNextRequest,
 * GetResponse, SetRequest, GetBulk, Inform, V2Trap, and Report.
 */

static void
snmppdu_print(u_char pduid, const u_char *np, u_int length, snmp_packet_t *pkt)
{
	struct be elem;
	int count = 0;

	/* reqId (Integer) */
	if ((count = asn1_parse(np, length, &elem)) < 0)
		return;
	if (elem.type != BE_INT) {
		fputs("[reqId!=INT]\n", stderr);
		return;
	}

	set_int32(&pkt->msg.scoped_pdu.pdu.req_id, count, &elem);

	length -= count;
	np += count;

	/* errorStatus (Integer) */
	if ((count = asn1_parse(np, length, &elem)) < 0)
		return;
	if (elem.type != BE_INT) {
		fputs("[errorStatus!=INT]\n", stderr);
		return;
	}

	set_int32(&pkt->msg.scoped_pdu.pdu.err_status, count, &elem);

	length -= count;
	np += count;

	/* errorIndex (Integer) */
	if ((count = asn1_parse(np, length, &elem)) < 0)
		return;
	if (elem.type != BE_INT) {
		fputs("[errorIndex!=INT]\n", stderr);
		return;
	}

	set_int32(&pkt->msg.scoped_pdu.pdu.err_index, count, &elem);

	length -= count;
	np += count;

	varbind_print(pduid, np, length, pkt);
	return;
}

/*
 * Decode SNMP Trap PDUs, which require some special treatment.
 */

static void
trappdu_print(const u_char *np, u_int length, snmp_packet_t *pkt)
{
	struct be elem;
	int count = 0;

	/* enterprise (oid) */
	if ((count = asn1_parse(np, length, &elem)) < 0)
		return;
	if (elem.type != BE_OID) {
		fputs("[enterprise!=OID]\n", stderr);
		return;
	}

	set_oid(&pkt->msg.scoped_pdu.pdu.enterprise, count, &elem);

	length -= count;
	np += count;

	/* agent-addr (inetaddr) */
	if ((count = asn1_parse(np, length, &elem)) < 0)
		return;
	if (elem.type != BE_INETADDR) {
		fputs("[agent-addr!=INETADDR]\n", stderr);
		return;
	}

	set_ipaddr(&pkt->msg.scoped_pdu.pdu.agent_addr, count, &elem);

	length -= count;
	np += count;

	/* generic-trap (Integer) */
	if ((count = asn1_parse(np, length, &elem)) < 0)
		return;
	if (elem.type != BE_INT) {
		fputs("[generic-trap!=INT]\n", stderr);
		return;
	}

	set_int32(&pkt->msg.scoped_pdu.pdu.generic_trap, count, &elem);

	length -= count;
	np += count;

	/* specific-trap (Integer) */
	if ((count = asn1_parse(np, length, &elem)) < 0)
		return;
	if (elem.type != BE_INT) {
		fputs("[specific-trap!=INT]\n", stderr);
		return;
	}

	set_int32(&pkt->msg.scoped_pdu.pdu.specific_trap, count, &elem);

	length -= count;
	np += count;

	/* time-stamp (TimeTicks) */
	if ((count = asn1_parse(np, length, &elem)) < 0)
		return;
	if (elem.type != BE_UNS) {
		fputs("[time-stamp!=TIMETICKS]\n", stderr);
		return;
	}

	set_int32(&pkt->msg.scoped_pdu.pdu.time_stamp, count, &elem);
 
	length -= count;
	np += count;

	varbind_print(TRAP, np, length, pkt);
	return;
}

/*
 * Decode SNMP PDUs used by all existing SNMP versions.
 */

static void
pdu_print(const u_char *np, u_int length, int version, snmp_packet_t *pkt)
{
	struct be pdu;
	int count = 0;

	/* PDU (Context) */
	if ((count = asn1_parse(np, length, &pdu)) < 0)
		return;
	if (pdu.type != BE_PDU) {
		fputs("[no PDU]\n", stderr);
		return;
	}
	if ((u_int)count < length)
		fprintf(stderr, "[%d extra after PDU]\n", length - count);

	pkt->msg.scoped_pdu.pdu.attr.blen
	    = length;
	pkt->msg.scoped_pdu.pdu.attr.vlen
	    = pdu.asnlen;
	pkt->msg.scoped_pdu.pdu.attr.flags
	    = SNMP_FLAG_VALUE | SNMP_FLAG_BLEN | SNMP_FLAG_VLEN;
	switch (pdu.id) {
	case TRAP:
	    pkt->msg.scoped_pdu.pdu.type = SNMP_PDU_TRAP1;
	    break;
	case GETREQ:
	    pkt->msg.scoped_pdu.pdu.type = SNMP_PDU_GET;
	    break;
	case GETNEXTREQ:
	    pkt->msg.scoped_pdu.pdu.type = SNMP_PDU_GETNEXT;
	    break;
	case GETRESP:
	    pkt->msg.scoped_pdu.pdu.type = SNMP_PDU_RESPONSE;
	    break;
	case SETREQ:
	    pkt->msg.scoped_pdu.pdu.type = SNMP_PDU_SET;
	    break;
	case GETBULKREQ:
	    pkt->msg.scoped_pdu.pdu.type = SNMP_PDU_GETBULK;
	    break;
	case INFORMREQ:
	    pkt->msg.scoped_pdu.pdu.type = SNMP_PDU_INFORM;
	    break;
	case V2TRAP:
	    pkt->msg.scoped_pdu.pdu.type = SNMP_PDU_TRAP2;
	    break;
	case REPORT:
	    pkt->msg.scoped_pdu.pdu.type = SNMP_PDU_REPORT;
	    break;
	default:
	    pkt->msg.scoped_pdu.pdu.attr.flags &= ~SNMP_FLAG_VALUE;
	}
	
	/* descend into PDU */
	length = pdu.asnlen;
	np = (u_char *)pdu.data.raw;

	if (version == SNMP_VERSION_1 &&
	    (pdu.id == GETBULKREQ || pdu.id == INFORMREQ ||
	     pdu.id == V2TRAP || pdu.id == REPORT)) {
	        fprintf(stderr, "[v2 PDU in v1 message]\n");
		return;
	}

	if (version == SNMP_VERSION_2 && pdu.id == TRAP) {
	        fprintf(stderr, "[v1 PDU in v2 message]\n");
		return;
	}

	switch (pdu.id) {
	case TRAP:
		trappdu_print(np, length, pkt);
		break;
	case GETREQ:
	case GETNEXTREQ:
	case GETRESP:
	case SETREQ:
	case GETBULKREQ:
	case INFORMREQ:
	case V2TRAP:
	case REPORT:
		snmppdu_print(pdu.id, np, length, pkt);
		break;
	}
}

/*
 * Decode a scoped SNMP PDU as defined in RFC 3412.
 */

static void
scopedpdu_print(const u_char *np, u_int length, int version, snmp_packet_t *pkt)
{
	struct be elem;
	int count = 0;

	/* Sequence */
	if ((count = asn1_parse(np, length, &elem)) < 0)
		return;
	if (elem.type != BE_SEQ) {
		fputs("[!scoped PDU]\n", stderr);
		return;
	}

	pkt->msg.scoped_pdu.attr.blen
	    = length;
	pkt->msg.scoped_pdu.attr.vlen
	    = elem.asnlen;
	pkt->msg.scoped_pdu.attr.flags
	    = SNMP_FLAG_VALUE | SNMP_FLAG_BLEN | SNMP_FLAG_VLEN;
	
	length = elem.asnlen;
	np = (u_char *)elem.data.raw;

	/* contextEngineID (OCTET STRING) */
	if ((count = asn1_parse(np, length, &elem)) < 0)
		return;
	if (elem.type != BE_STR) {
		fputs("[contextEngineID!=STR]\n", stderr);
		return;
	}

	set_octs(&pkt->msg.scoped_pdu.context_engine_id, count, &elem);

	length -= count;
	np += count;

	/* contextName (OCTET STRING) */
	if ((count = asn1_parse(np, length, &elem)) < 0)
		return;
	if (elem.type != BE_STR) {
		fputs("[contextName!=STR]\n", stderr);
		return;
	}

	set_octs(&pkt->msg.scoped_pdu.context_name, count, &elem);

	length -= count;
	np += count;

	pdu_print(np, length, version, pkt);
}

/*
 * Decode community-based security SNMP message header (SNMPv1 /
 * SNMPv2c) and pass on to the pdu decoding function.
 */

static void
v12msg_parse(const u_char *np, u_int length, int version, snmp_packet_t *pkt)
{
	struct be elem;
	int count = 0;

	/* Community (String) */
	if ((count = asn1_parse(np, length, &elem)) < 0)
		return;
	if (elem.type != BE_STR) {
		fputs("[comm!=STR]\n", stderr);
		return;
	}

	set_octs(&pkt->msg.community, count, &elem);

	length -= count;
	np += count;

	pdu_print(np, length, version, pkt);
}

/*
 * Decode the SNMP version 3 (SNMPv3) user-based security model (USM)
 * header.
 */

static void
usm_print(const u_char *np, u_int length, int indent)
{
        struct be elem;
	int count = 0;

	/* Sequence */
	if ((count = asn1_parse(np, length, &elem)) < 0)
		return;
	if (elem.type != BE_SEQ) {
		fputs("[!usm]\n", stderr);
		return;
	}
	xml_elem_start(indent, "usm", count, elem.asnlen);
	length = elem.asnlen;
	np = (u_char *)elem.data.raw;

	/* msgAuthoritativeEngineID (OCTET STRING) */
	if ((count = asn1_parse(np, length, &elem)) < 0)
		return;
	if (elem.type != BE_STR) {
		fputs("[msgAuthoritativeEngineID!=STR]\n", stderr);
		return;
	}
	xml_leaf(indent+2, "auth-engine-id", count, elem.asnlen,
		 "%s", hexify(elem.asnlen, elem.data.str));
	length -= count;
	np += count;

	/* msgAuthoritativeEngineBoots (INTEGER) */
	if ((count = asn1_parse(np, length, &elem)) < 0)
		return;
	if (elem.type != BE_INT) {
		fputs("[msgAuthoritativeEngineBoots!=INT]\n", stderr);
		return;
	}
	xml_leaf(indent+2, "auth-engine-boots", count, elem.asnlen,
		 "%d", elem.data.integer);
	length -= count;
	np += count;

	/* msgAuthoritativeEngineTime (INTEGER) */
	if ((count = asn1_parse(np, length, &elem)) < 0)
		return;
	if (elem.type != BE_INT) {
		fputs("[msgAuthoritativeEngineTime!=INT]\n", stderr);
		return;
	}
	xml_leaf(indent+2, "auth-engine-time", count, elem.asnlen,
		 "%d", elem.data.integer);
	length -= count;
	np += count;

	/* msgUserName (OCTET STRING) */
	if ((count = asn1_parse(np, length, &elem)) < 0)
		return;
	if (elem.type != BE_STR) {
		fputs("[msgUserName!=STR]\n", stderr);
		return;
	}
	xml_leaf(indent+2, "user", count, elem.asnlen,
		 "%s", hexify(elem.asnlen, elem.data.str));
	length -= count;
        np += count;

	/* msgAuthenticationParameters (OCTET STRING) */
	if ((count = asn1_parse(np, length, &elem)) < 0)
		return;
	if (elem.type != BE_STR) {
		fputs("[msgAuthenticationParameters!=STR]\n", stderr);
		return;
	}
	xml_leaf(indent+2, "auth-params", count, elem.asnlen,
		 "%s", hexify(elem.asnlen, elem.data.str));
	length -= count;
        np += count;

	/* msgPrivacyParameters (OCTET STRING) */
	if ((count = asn1_parse(np, length, &elem)) < 0)
		return;
	if (elem.type != BE_STR) {
		fputs("[msgPrivacyParameters!=STR]\n", stderr);
		return;
	}
	xml_leaf(indent+2, "priv-params", count, elem.asnlen,
		 "%s", hexify(elem.asnlen, elem.data.str));
	length -= count;
        np += count;

	if ((u_int)count < length)
		fprintf(stderr, "[%d extra after usm SEQ]\n", length - count);

	xml_elem_end(indent, "usm");
}

/*
 * Decode SNMP version 3 (SNMPv3) message header and pass on to the
 * scoped pdu decoding function.
 */

static void
v3msg_print(const u_char *np, u_int length, snmp_packet_t *pkt)
{
	struct be elem;
	int count = 0;
	u_char flags;
	int model;
	const u_char *xnp = np;
	int xlength = length;

	/* Sequence */
	if ((count = asn1_parse(np, length, &elem)) < 0)
		return;
	if (elem.type != BE_SEQ) {
		fputs("[!message]", stderr);
		asn1_print(&elem);
		return;
	}

#if 0		/* XXX fixme XXX */
	xml_elem_start(indent, "message", count, elem.asnlen);
#endif
	length = elem.asnlen;
	np = (u_char *)elem.data.raw;

	/* msgID (INTEGER) */
	if ((count = asn1_parse(np, length, &elem)) < 0)
		return;
	if (elem.type != BE_INT) {
		fputs("[msgID!=INT]\n", stderr);
		return;
	}

	set_uint32(&pkt->msg.msg_id, count, &elem);
	
	length -= count;
	np += count;

	/* msgMaxSize (INTEGER) */
	if ((count = asn1_parse(np, length, &elem)) < 0)
		return;
	if (elem.type != BE_INT) {
		fputs("[msgMaxSize!=INT]\n", stderr);
		return;
	}

	set_uint32(&pkt->msg.msg_max_size, count, &elem);
	
	length -= count;
	np += count;

	/* msgFlags (OCTET STRING) */
	if ((count = asn1_parse(np, length, &elem)) < 0)
		return;
	if (elem.type != BE_STR) {
		fputs("[msgFlags!=STR]\n", stderr);
		return;
	}
	if (elem.asnlen != 1) {
	        fprintf(stderr, "[msgFlags size %d]\n", elem.asnlen);
		return;
	}
	flags = elem.data.str[0];
	if (flags != 0x00 && flags != 0x01 && flags != 0x03
	    && flags != 0x04 && flags != 0x05 && flags != 0x07) {
		fprintf(stderr, "[msgFlags=0x%02X]\n", flags);
		return;
	}

	set_octs(&pkt->msg.msg_flags, count, &elem);

	length -= count;
	np += count;

	/* msgSecurityModel (INTEGER) */
	if ((count = asn1_parse(np, length, &elem)) < 0)
		return;
	if (elem.type != BE_INT) {
		fputs("[msgSecurityModel!=INT]\n", stderr);
		asn1_print(&elem);
		return;
	}
	
	set_uint32(&pkt->msg.msg_sec_model, count, &elem);

	length -= count;
	np += count;

	if ((u_int)count < length) {
		fprintf(stderr, "[%d extra after message SEQ]\n",
			length - count);
	}

#if 0
	if (model == 3) {
	    if (vflag) {
		fputs("{ USM ", stdout);
	    }
	} else {
	    printf("[security model %d]", model);
            return;
	}
#endif

	np = xnp + (np - xnp);
	length = xlength - (np - xnp);

	/* xxx */

	/* msgSecurityParameters (OCTET STRING) */
	if ((count = asn1_parse(np, length, &elem)) < 0)
		return;
	if (elem.type != BE_STR) {
		fputs("[msgSecurityParameters!=STR]", stdout);
		asn1_print(&elem);
		return;
	}
	length -= count;
	np += count;

	if (model == 3) {
		usm_print(elem.data.str, elem.asnlen, 4242);
	}

	scopedpdu_print(np, length, 3, pkt);
}

/*
 * Decode the outer SNMP message header and pass on to message version
 * specific printing routines. Error messages are send to stderr and
 * further processing stops.
 */

static void
snmp_parse(const u_char *np, u_int length, snmp_packet_t *pkt)
{
	struct be elem;
	int count = 0;
	int version = 0;

	truncated = 0;

	/* initial Sequence */
	if ((count = asn1_parse(np, length, &elem)) < 0)
		return;
	if (elem.type != BE_SEQ) {
		fputs("[!init SEQ]\n", stderr);
		return;
	}
	if ((u_int)count < length)
		fprintf(stderr, "[%d extra after iSEQ]\n", length - count);

	pkt->msg.attr.blen = length;
	pkt->msg.attr.vlen = elem.asnlen;
	pkt->msg.attr.flags = SNMP_FLAG_BLEN | SNMP_FLAG_VLEN;

        /* descend */
	length = elem.asnlen;
	np = (u_char *)elem.data.raw;

	/* Version (INTEGER) */
	if ((count = asn1_parse(np, length, &elem)) < 0)
		return;
	if (elem.type != BE_INT) {
		fputs("[version!=INT]\n", stderr);
		return;
	}

	set_int32(&pkt->msg.version, count, &elem);

	switch (elem.data.integer) {
	case SNMP_VERSION_1:
	case SNMP_VERSION_2:
	case SNMP_VERSION_3:
		break;
	default:
	        fprintf(stderr, "[version = %d]\n", elem.data.integer);
		return;
	}
	version = elem.data.integer;
	length -= count;
	np += count;

	switch (version) {
	case SNMP_VERSION_1:
        case SNMP_VERSION_2:
		v12msg_parse(np, length, version, pkt);
		break;
	case SNMP_VERSION_3:
		v3msg_print(np, length, pkt);
		break;
	default:
	        fprintf(stderr, "[version = %d]\n", elem.data.integer);
		break;
	}
}

/*
 * Callback invoked by libnids for every UPD datagram that we have
 * received. Note that the datagram might have been reassembled from
 * multiple IP packets. The time information belongs to the last
 * fragment we have received.
 */

static void
udp_callback(struct tuple4 * addr, char * buf, int len, void *ignore)
{
    snmp_packet_t _pkt, *pkt = &_pkt;
    struct sockaddr_in *sock = NULL;

    pkt->time.tv_sec = nids_last_pcap_header->ts.tv_sec;
    pkt->time.tv_usec = nids_last_pcap_header->ts.tv_usec;

    sock = (struct sockaddr_in *) &pkt->src;
    sock->sin_family = AF_INET;
    sock->sin_addr.s_addr = addr->saddr;
    sock->sin_port = addr->source;

    sock = (struct sockaddr_in *) &pkt->dst;
    sock->sin_family = AF_INET;
    sock->sin_addr.s_addr = addr->daddr;
    sock->sin_port = addr->dest;

    pkt->attr.flags = SNMP_FLAG_SADDR | SNMP_FLAG_SPORT
	    | SNMP_FLAG_DADDR | SNMP_FLAG_DPORT;

    snmp_parse((unsigned char *) buf, len, pkt);

    if (user_callback) {
	user_callback(pkt, user_data);
    }
}

/*
 * Entry point which reads a pcap file, applies the given pcap filter
 * and then calls the callback func for each SNMP message, passing the
 * user data pointer as well.
 */

void
snmp_pcap_read_file(const char *file, const char *filter,
		    snmp_callback func, void *data)
{
    nids_params.filename = (char *) file;
    nids_params.device = NULL;
    nids_params.pcap_filter = (char *) filter;

    user_callback = func;
    user_data = data;
	
    if (! nids_init()) {
	fprintf(stderr, "libnids initialization failed: %s\n", nids_errbuf);
	exit(1);
    }

    nids_register_udp(udp_callback);
    nids_run();
}
