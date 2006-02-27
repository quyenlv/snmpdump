/*
 * deserializer.c --
 *
 * A simple C program to deserialize XML representation of SNMP
 * traffic traces.
 *
 * (c) 2006 Juergen Schoenwaelder <j.schoenwaelder@iu-bremen.de>
 * (c) 2006 Matus Harvan <m.harvan@iu-bremen.de>
 */

/*
 * compile with: gcc -g `xml2-config --cflags` `xml2-config --libs`
 *	deserializer.c -o deserializer
 */

//#include <config.h>

#include <libxml/xmlreader.h>
#include <assert.h>
#include <string.h>
#include "snmp.h"
#include <netdb.h> /* maybe this should go into snmp.h */

static const char *progname = "deserializer";

#define debug 1
#ifdef debug
#define DEBUG(format, ...) fprintf (stderr, format, ## __VA_ARGS__)
#else
#define DEBUG(format, ...)
#endif

static enum {
	IN_NONE,
	IN_SNMPTRACE,
	IN_PACKET,
	IN_SNMP,
	IN_VERSION,
	IN_COMMUNITY,
	
	/* add SNMPv3 stuff here */
	IN_MESSAGE,
	IN_MSG_IG,
	IN_MAX_SIZE,
	IN_FLAGS,
	IN_SEC_MODEL,
	
	IN_TRAP,
	IN_ENTERPRISE,
	IN_AGENT_ADDR,
	IN_GENERIC_TRAP,
	IN_SPECIFIC_TRAP,
	IN_TIME_STAMP,
	IN_VARIABLE_BINDINGS,
	IN_GET_REQUEST,
	IN_GET_NEXT_REQUEST,
	IN_GET_BULK_REQUEST,
	IN_SET_REQUEST,
	IN_INFORM,
	IN_TRAP2,
	IN_RESPONSE,
	IN_REPORT,
	IN_REQUEST_ID,
	IN_ERROR_STATUS,
	IN_ERROR_INDEX,
	IN_VARBIND,
	IN_NAME,
	IN_NULL,
	IN_INTEGER32,
	IN_UNSIGNED32,
	IN_UNSIGNED64,
	IN_IPADDRESS,
	IN_OCTET_STRING,
	IN_OBJECT_IDENTIFIER,
	IN_NO_SUCH_OBJECT,
	IN_NO_SUCH_INSTANCE,
	IN_END_OF_MIB_VIEW,
	IN_VALUE
} state = IN_NONE;

static int version[3];
static int total;

/*
static int
UTF8atoi(const xmlChar* xmlstr) {
    int i=0;
    int out = 0;
    for(i=0;xmlstr[i] >= '0' && xmlstr[i] <= '9';i++) {
	out *= 10;
	out += xmlstr[i] - '0';
    }
    return out;
}
*/

/*
 * deallocate packet_t and all its data members
 * TODO: (xml)string deallocation (also in other parts of packet)
 */
void
snmp_packet_free(packet_t* packet) {
    snmp_varbind_t* varbind;
    snmp_varbind_t* next;
    assert(packet);
    /* free varbinds */
    next = packet->message.pdu.varbindings.varbind;
    while (next) {
	varbind = next;
	//DEBUG("freeing... varbind: %x\n", varbind);
	if (varbind->value) {
	    if (varbind->type == SNMP_TYPE_OCTS) {
		if (((snmp_octs_t*)(varbind->value))->value) {
		    //free(((snmp_octs_t*)(varbind->value))->value);
		    xmlFree(((snmp_octs_t*)(varbind->value))->value);
		}
	    }
	    assert(varbind->type == SNMP_TYPE_INT32
		   || varbind->type == SNMP_TYPE_UINT32
		   || varbind->type == SNMP_TYPE_UINT64
		   || varbind->type == SNMP_TYPE_IPADDR
		   || varbind->type == SNMP_TYPE_OCTS
		   || varbind->type == SNMP_TYPE_OID);
	    //DEBUG("freeing... varbind->value: %x\n", varbind->value);
	    free(varbind->value);
	}
	next = next->next;
	free(varbind);
    }
    /* free community string */
    if (packet->message.community.attr.flags & SNMP_FLAG_VALUE) {
	assert(packet->message.community.value);
	xmlFree(packet->message.community.value);
    }
    free(packet);
}

static void
set_state(int newState) {
    state = newState;
}

/*
 * parse node currently in reader for snmp_int32_t
 */
static void
process_snmp_int32(xmlTextReaderPtr reader, snmp_int32_t* snmpint) {
    char *end;
    assert(snmpint);
    const xmlChar* value = xmlTextReaderConstValue(reader);
    if (value) {
	/* snmpint->value = atoi((char *) value); */
	snmpint->value = (int32_t) strtol((char *) value, &end, 10);
	if (*end == '\0') {
	    snmpint->attr.flags |= SNMP_FLAG_VALUE;
	}
    }
}

/*
 * parse node currently in reader for snmp_uint32_t
 */
static void
process_snmp_uint32(xmlTextReaderPtr reader, snmp_uint32_t* snmpint) {
    char *end;
    DEBUG("process_snmp_uint32(): snmpint:%x\n", snmpint);
    assert(snmpint);
    const xmlChar* value = xmlTextReaderConstValue(reader);
    if (value) {
	snmpint->value = (uint32_t) strtoul((char *) value, &end, 10);
	if (*end == '\0') {
	    snmpint->attr.flags |= SNMP_FLAG_VALUE;
	}
    }
}

/*
 * parse node currently in reader for snmp_uint64_t
 */
static void
process_snmp_uint64(xmlTextReaderPtr reader, snmp_uint64_t* snmpint) {
    char *end;
    assert(snmpint);
    const xmlChar* value = xmlTextReaderConstValue(reader);
    if (value) {
	snmpint->value = (uint64_t) strtoull((char *) value, &end, 10);
	if (*end == '\0') {
	    snmpint->attr.flags |= SNMP_FLAG_VALUE;
	}
    }
}

/*
 * parse node currently in reader for snmp_ipaddr_t
 */
static void
process_snmp_ipaddr(xmlTextReaderPtr reader, snmp_ipaddr_t* snmpaddr) {
    assert(snmpaddr);
    const xmlChar* value = xmlTextReaderConstValue(reader);
    if (value) {
	if (inet_pton(AF_INET, value, &(snmpaddr->value)) > 0) {
	    snmpaddr->attr.flags |= SNMP_FLAG_VALUE;
	} else if (inet_pton(AF_INET6, value,  &(snmpaddr->value)) > 0) {
	    snmpaddr->attr.flags |= SNMP_FLAG_VALUE;
	}
    }
}

/*
 * parse node currently in reader for snmp_octs_t
 * we're using the xmlString, maybe we should rather copy it !!!
 * user has to call xmlFree in this string !!!
 */
static void
process_snmp_octs(xmlTextReaderPtr reader, snmp_octs_t* snmpstr) {
    assert(snmpstr);
    xmlChar* value = xmlTextReaderValue(reader);
    if (value) {
	snmpstr->value = value;
	snmpstr->attr.flags |= SNMP_FLAG_VALUE;
    }
}

/*
 * parse node currently in reader for snmp_oid_t
 */
static void
process_snmp_oid(xmlTextReaderPtr reader, snmp_oid_t* snmpoid) {
    int i;
    char *end;
    assert(snmpoid);
    const xmlChar* value = xmlTextReaderConstValue(reader);
    if (value) {
	snmpoid->value[0] = (uint32_t) strtoul((const char *) value, &end, 10);
	if (*end == '\0' || *end == '.') {
	    /* maybe this should be "if (!...) return" rather than assert */
	    assert(snmpoid->value[0] >= 0 && snmpoid->value[0] <= 2);
	}
	for(i=1;i<128 && *end == '.';i++) {
	    value = (xmlChar*) end;
	    //end = NULL;
	    snmpoid->value[i] = (uint32_t) strtoul((const char *) value, &end, 10);
	}
	if (*end == '\0') {
	    snmpoid->attr.flags |= SNMP_FLAG_VALUE;
	}
    }
}

/*
  parse node currently in reader for snmp_attr_t blen and vlen  
 */
static void
process_snmp_attr(xmlTextReaderPtr reader, snmp_attr_t* attr) {
    xmlChar* strattr;
    /* attributes */
    /* blen */
    assert(attr);
    strattr = xmlTextReaderGetAttribute(reader, BAD_CAST("blen"));
    if (strattr) {
	attr->blen = atoi((char*)strattr);
	attr->flags |= SNMP_FLAG_BLEN;
	//DEBUG("snmp-blen: %d\n", attr->blen);
	xmlFree(strattr);
    }
    /* vlen */
    strattr = xmlTextReaderGetAttribute(reader, BAD_CAST("vlen"));
    if (strattr) {
	attr->vlen = atoi((char*)strattr);
	attr->flags |= SNMP_FLAG_VLEN;
	//DEBUG("snmp-vlen: %d\n", attr->vlen);
	xmlFree(strattr);
    }
}

/*
 * process node currently in reader by filling in packet_t structure
 * allocates a new packet_t when new "packet" xml node is reached
 * when end of "packet" xml node is reached, callback function is called
 */
static void
process_node(xmlTextReaderPtr reader, packet_t** packet,
	    snmp_varbind_t** varbind) {
    const xmlChar *name, *value;
    xmlChar* attr;
    int i;
    char *end;

    /* 1, 3, 8, 14, 15 */
    switch (xmlTextReaderNodeType(reader)) {
    case XML_READER_TYPE_ELEMENT:
	/*
	 * check what node we have:
	 * first has to come snmptrace
	 * node packet - allocate new snmp_msg_t
	 * other nodes - allocate respective storage part within
	 *		 current snmp_msg_t and fill in data
	 */
	name = xmlTextReaderConstName(reader);
	if (name == NULL)
	    name = BAD_CAST "--";
	/* packet */
	if (name && xmlStrcmp(name, BAD_CAST("packet")) == 0) {
	    DEBUG("in PACKET\n");
	    set_state(IN_PACKET);
	    *packet = (packet_t*) malloc(sizeof(packet_t));
	    assert(*packet);
	    memset(*packet, 0, sizeof(packet_t));
	    *varbind = NULL;
	    /* attributes */
	    /* date */
	    attr = xmlTextReaderGetAttribute(reader, BAD_CAST("date"));
	    if (attr) {
		strptime(attr, "%FT%H:%M:%S", &((*packet)->time));
		(*packet)->message.attr.flags |= SNMP_FLAG_DATE;
		xmlFree(attr);
	    }
	    /* delta */
	    attr = xmlTextReaderGetAttribute(reader, BAD_CAST("date"));
	    if (attr) {
		(*packet)->delta =
		    (unsigned long) strtoll((char*) attr, &end, 10);
		assert(strtoll((char*) attr, &end, 10) >= 0);
		if (*end == '\0') {
		    (*packet)->message.attr.flags |= SNMP_FLAG_DELTA;
		}
		xmlFree(attr);
	    }
	    //value = xmlTextReaderGetAttribute(reader, BAD_CAST("delta"));
	/* src */
	} else if (name && xmlStrcmp(name, BAD_CAST("src")) == 0) {
	    DEBUG( "in SRC\n");
	    /* no state */
	    assert(state == IN_PACKET);
	    assert(*packet);
	    /* attributes */
	    /* ip */
	    attr = xmlTextReaderGetAttribute(reader, BAD_CAST("ip"));
	    if (attr) {
		if (inet_pton(AF_INET, attr, &((*packet)->src)) > 0) {
		    (*packet)->message.attr.flags |= SNMP_FLAG_SADDR;
		} else if (inet_pton(AF_INET6, attr, &((*packet)->src)) > 0) {
			(*packet)->message.attr.flags |= SNMP_FLAG_SADDR;
		}
		//DEBUG("ip: %s\n", inet_ntoa((*packet)->src));
		xmlFree(attr);
	    }
	    /* port */
	    attr = xmlTextReaderGetAttribute(reader, BAD_CAST("port"));
	    if (attr) {
		/* sin_port is the same for both ipv4 and ipv6 */
		
		((struct sockaddr_in*)(&((*packet)->src)))->sin_port =
		    htons(atoi((char*) attr));
		(*packet)->message.attr.flags |= SNMP_FLAG_SPORT;
		
		/* this swtich should be unneccessary
		switch((*packet)->src.ss_family)
		    {
		    case AF_INET6:
			((struct sockaddr_in6)(*packet)->src).sin6_port =
			    atoi(attr);
			break;
		    default:
			((struct sockaddr_in)(*packet)->src).sin_port =
			    atoi(attr);
			break;
		    }
		*/
		xmlFree(attr);
	    }
	/* dst */
	} else if (name && xmlStrcmp(name, BAD_CAST("dst")) == 0) {
	    DEBUG("in DST\n");
	    /* no state */
	    assert(state == IN_PACKET);
	    assert((*packet));
	    /* attributes */
	    /* ip */
	    attr = xmlTextReaderGetAttribute(reader, BAD_CAST("ip"));
	    if (attr) {
		if (inet_pton(AF_INET, attr, &((*packet)->dst)) > 0) {
		    (*packet)->message.attr.flags |= SNMP_FLAG_DADDR;
		} else if (inet_pton(AF_INET6, attr, &((*packet)->dst)) > 0) {
		    (*packet)->message.attr.flags |= SNMP_FLAG_DADDR;
		}
		//DEBUG("ip: %s\n", inet_ntoa((*packet)->dst));
		xmlFree(attr);
	    }
	    /* port */
	    attr = xmlTextReaderGetAttribute(reader, BAD_CAST("port"));
	    if (attr) {
		/* sin_port is the same for both ipv4 and ipv6 */
		((struct sockaddr_in*)(&((*packet)->dst)))->sin_port =
		    htons(atoi((char*) attr));
		(*packet)->message.attr.flags |= SNMP_FLAG_DPORT;
		xmlFree(attr);
	    }
	/* snmp */
	} else if (name && xmlStrcmp(name, BAD_CAST("snmp")) == 0) {
	    DEBUG("in SNMP\n");
	    assert(state == IN_PACKET);
	    set_state(IN_SNMP);
	    assert((*packet));
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*packet)->message.attr));
	/* version */
	} else if (name && xmlStrcmp(name, BAD_CAST("version")) == 0) {
	    assert(state == IN_SNMP);
	    set_state(IN_VERSION);
	    assert((*packet));
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*packet)->message.version.attr));
	/* community */
	} else if (name && xmlStrcmp(name, BAD_CAST("community")) == 0) {
	    set_state(IN_COMMUNITY);
	    assert((*packet));
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*packet)->message.community.attr));
	/* trap */
	} else if (name && xmlStrcmp(name, BAD_CAST("trap")) == 0) {
	    set_state(IN_TRAP);
	    assert((*packet));
	    (*packet)->message.pdu.type = SNMP_PDU_TRAP1;
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*packet)->message.pdu.attr));
	/* enterprise */
	} else if (name && xmlStrcmp(name, BAD_CAST("enterprise")) == 0) {
	    set_state(IN_ENTERPRISE);
	    assert((*packet));
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*packet)->message.pdu.enterprise.attr));
	/* agent-addr */
	} else if (name && xmlStrcmp(name, BAD_CAST("agent-addr")) == 0) {
	    set_state(IN_AGENT_ADDR);
	    assert((*packet));
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*packet)->message.pdu.agent_addr.attr));
	/* generic-trap */
	} else if (name && xmlStrcmp(name, BAD_CAST("generic-trap")) == 0) {
	    set_state(IN_GENERIC_TRAP);
	    assert((*packet));
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader,
			    &((*packet)->message.pdu.generic_trap.attr));
	/* specific-trap */
	} else if (name && xmlStrcmp(name, BAD_CAST("specific-trap")) == 0) {
	    set_state(IN_SPECIFIC_TRAP);
	    assert((*packet));
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader,
			    &((*packet)->message.pdu.specific_trap.attr));
	/* time-stamp */
	} else if (name && xmlStrcmp(name, BAD_CAST("time-stamp")) == 0) {
	    set_state(IN_TIME_STAMP);
	    assert(*packet);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader,
			    &((*packet)->message.pdu.time_stamp.attr));
	/*
	 * get-request | get-next-request | get-bulk-request |
         * set-request | inform | trap2 | response | report
	 */
	} else if (name &&
		   (xmlStrcmp(name, BAD_CAST("get-request")) == 0
		    || xmlStrcmp(name, BAD_CAST("get-next-request")) == 0
		    || xmlStrcmp(name, BAD_CAST("get-bulk-request")) == 0
		    || xmlStrcmp(name, BAD_CAST("set-request")) == 0
		    || xmlStrcmp(name, BAD_CAST("inform")) == 0
		    || xmlStrcmp(name, BAD_CAST("trap2")) == 0
		    || xmlStrcmp(name, BAD_CAST("response")) == 0
		    || xmlStrcmp(name, BAD_CAST("report")) == 0
		    )) {
	    /* state */
	    assert((*packet));
	    if (xmlStrcmp(name, BAD_CAST("get-request")) == 0) {
		set_state(IN_GET_REQUEST);
		(*packet)->message.pdu.type = SNMP_PDU_GET;
	    } else if (xmlStrcmp(name, BAD_CAST("get-next-request")) == 0) {
		set_state(IN_GET_NEXT_REQUEST);
		(*packet)->message.pdu.type = SNMP_PDU_GETNEXT;
	    } else if (xmlStrcmp(name, BAD_CAST("get-bulk-request")) == 0) {
		set_state(IN_GET_BULK_REQUEST);
		(*packet)->message.pdu.type = SNMP_PDU_GETBULK;
	    } else if (xmlStrcmp(name, BAD_CAST("set-request")) == 0) {
		set_state(IN_SET_REQUEST);
		(*packet)->message.pdu.type = SNMP_PDU_SET;
	    } else if (xmlStrcmp(name, BAD_CAST("inform")) == 0) {
		set_state(IN_INFORM);
		(*packet)->message.pdu.type = SNMP_PDU_INFORM;
	    } else if (xmlStrcmp(name, BAD_CAST("trap2")) == 0) {
		set_state(IN_TRAP2);
		(*packet)->message.pdu.type = SNMP_PDU_TRAP2;
	    } else if (xmlStrcmp(name, BAD_CAST("response")) == 0) {
		set_state(IN_RESPONSE);
		(*packet)->message.pdu.type = SNMP_PDU_RESPONSE;
	    } else if (xmlStrcmp(name, BAD_CAST("report")) == 0) {
		set_state(IN_REPORT);
		(*packet)->message.pdu.type = SNMP_PDU_REPORT;
	    }
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader,
			    &((*packet)->message.pdu.attr));
	/* request-id */
	} else if (name && xmlStrcmp(name, BAD_CAST("request-id")) == 0) {
	    set_state(IN_REQUEST_ID);
	    assert(*packet);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader,
			    &((*packet)->message.pdu.req_id.attr));
	/* error-status */
	} else if (name && xmlStrcmp(name, BAD_CAST("error-status")) == 0) {
	    set_state(IN_ERROR_STATUS);
	    assert(*packet);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader,
			    &((*packet)->message.pdu.err_status.attr));
	/* error-index */
	} else if (name && xmlStrcmp(name, BAD_CAST("error-index")) == 0) {
	    set_state(IN_ERROR_INDEX);
	    assert(*packet);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader,
			    &((*packet)->message.pdu.err_index.attr));
	/* variable-bindings */
	} else if (name
		   && xmlStrcmp(name, BAD_CAST("variable-bindings")) == 0) {
	    set_state(IN_VARIABLE_BINDINGS);
	    assert(*packet);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader,
			    &((*packet)->message.pdu.varbindings.attr));
	/* varbind */
	} else if (name && xmlStrcmp(name, BAD_CAST("varbind")) == 0) {
	    set_state(IN_VARBIND);
	    assert(*packet);
	    if (*varbind != NULL) {
		(*varbind)->next =
		    (snmp_varbind_t*) malloc(sizeof(snmp_varbind_t));
		*varbind = (*varbind)->next;
	    } else {
		*varbind = (snmp_varbind_t*) malloc(sizeof(snmp_varbind_t));
		(*packet)->message.pdu.varbindings.varbind = *varbind;
	    }
	    assert(*varbind);
	    memset(*varbind,0,sizeof(snmp_varbind_t));
	    //DEBUG("malloc... *varbind: %x\n", *varbind);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*varbind)->attr));
	/* varbind - name */
	} else if (name && xmlStrcmp(name, BAD_CAST("name")) == 0) {
	    assert(state == IN_VARBIND);
	    set_state(IN_NAME);
	    assert(*packet);
	    assert(*varbind);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*varbind)->name.attr));
	/* varbind (- value) - null */
	} else if (name && xmlStrcmp(name, BAD_CAST("null")) == 0) {
	    assert(state == IN_NAME); /* maybe not needed/wanted */
	    /* we should also check if parrent is varbind */
	    set_state(IN_NULL); 
	    assert(*packet);
	    assert(*varbind);
	    (*varbind)->type = SNMP_TYPE_NULL;
	    assert((*varbind)->value == NULL);
	    /* should be empty */
	/* varbind (- value) - integer32 */
	} else if (name && xmlStrcmp(name, BAD_CAST("integer32")) == 0) {
	    DEBUG("in INTEGER32\n");
	    assert(state == IN_NAME); /* maybe not needed/wanted */
	    /* we should also check if parrent is varbind */
	    set_state(IN_INTEGER32); 
	    assert(*packet);
	    assert(*varbind);
	    (*varbind)->type = SNMP_TYPE_INT32;
	    (*varbind)->value = (snmp_int32_t*) malloc(sizeof(snmp_int32_t));
	    assert((*varbind)->value);
	    memset((*varbind)->value,0,sizeof(snmp_int32_t));
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader,
			    &(((snmp_int32_t*)(*varbind)->value)->attr));
	/* varbind (- value) - unsigned32 */
	} else if (name && xmlStrcmp(name, BAD_CAST("unsigned32")) == 0) {
	    DEBUG("in UNSIGNED32\n");
	    assert(state == IN_NAME); /* maybe not needed/wanted */
	    /* we should also check if parrent is varbind */
	    set_state(IN_UNSIGNED32); 
	    assert(*packet);
	    assert(*varbind);
	    (*varbind)->type = SNMP_TYPE_UINT32;
	    (*varbind)->value = (snmp_uint32_t*) malloc(sizeof(snmp_uint32_t));
	    assert((*varbind)->value);
	    memset((*varbind)->value,0,sizeof(snmp_uint32_t));
	    //DEBUG("malloc... (*varbind)->value: %x\n", (*varbind)->value);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader,
			    &(((snmp_uint32_t*)(*varbind)->value)->attr));
	/* varbind (- value) - unsigned64 */
	} else if (name && xmlStrcmp(name, BAD_CAST("unsigned64")) == 0) {
	    DEBUG("in UNSIGNED64\n");
	    assert(state == IN_NAME); /* maybe not needed/wanted */
	    /* we should also check if parrent is varbind */
	    set_state(IN_UNSIGNED64); 
	    assert(*packet);
	    assert(*varbind);
	    (*varbind)->type = SNMP_TYPE_UINT64;
	    (*varbind)->value = (snmp_uint64_t*) malloc(sizeof(snmp_uint64_t));
	    assert((*varbind)->value);
	    memset((*varbind)->value,0,sizeof(snmp_uint64_t));
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader,
			    &(((snmp_uint64_t*)(*varbind)->value)->attr));
	/* varbind (- value) - ipaddress */
	} else if (name && xmlStrcmp(name, BAD_CAST("ipaddress")) == 0) {
	    DEBUG("in IPADDRESS\n");
	    assert(state == IN_NAME); /* maybe not needed/wanted */
	    /* we should also check if parrent is varbind */
	    set_state(IN_IPADDRESS); 
	    assert(*packet);
	    assert(*varbind);
	    (*varbind)->type = SNMP_TYPE_IPADDR;
	    (*varbind)->value = (snmp_ipaddr_t*) malloc(sizeof(snmp_ipaddr_t));
	    assert((*varbind)->value);
	    memset((*varbind)->value,0,sizeof(snmp_ipaddr_t));
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader,
			    &(((snmp_ipaddr_t*)(*varbind)->value)->attr));
	/* varbind (- value) - octet-string */
	} else if (name && xmlStrcmp(name, BAD_CAST("octet-string")) == 0) {
	    DEBUG("in OCTET-STRING\n");
	    assert(state == IN_NAME); /* maybe not needed/wanted */
	    /* we should also check if parrent is varbind */
	    set_state(IN_OCTET_STRING); 
	    assert(*packet);
	    assert(*varbind);
	    (*varbind)->type = SNMP_TYPE_OCTS;
	    (*varbind)->value = (snmp_octs_t*) malloc(sizeof(snmp_octs_t));
	    assert((*varbind)->value);
	    memset((*varbind)->value,0,sizeof(snmp_octs_t));
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader,
			    &(((snmp_octs_t*)(*varbind)->value)->attr));
	/* varbind (- value) - object-identifier */
	} else if (name &&
		   xmlStrcmp(name, BAD_CAST("object-identifier")) == 0) {
	    DEBUG("in OBJECT-IDENTIFIER\n");
	    assert(state == IN_NAME); /* maybe not needed/wanted */
	    /* we should also check if parrent is varbind */
	    set_state(IN_OBJECT_IDENTIFIER); 
	    assert(*packet);
	    assert(*varbind);
	    (*varbind)->type = SNMP_TYPE_OID;
	    (*varbind)->value = (snmp_oid_t*) malloc(sizeof(snmp_oid_t));
	    assert((*varbind)->value);
	    memset((*varbind)->value,0,sizeof(snmp_oid_t));
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &(((snmp_oid_t*)(*varbind)->value)->attr));
	/* varbind (- value) - no-such-object */
	} else if (name && xmlStrcmp(name, BAD_CAST("no-such-object")) == 0) {
	    assert(state == IN_NAME); /* maybe not needed/wanted */
	    /* we should also check if parrent is varbind */
	    set_state(IN_NO_SUCH_OBJECT); 
	    assert(*packet);
	    assert(*varbind);
	    (*varbind)->type = SNMP_TYPE_NO_SUCH_OBJ;
	    assert((*varbind)->value == NULL);
	    /* should be empty */
	/* varbind (- value) - no-such-instance */
	} else if (name && xmlStrcmp(name, BAD_CAST("no-such-instance")) == 0){
	    assert(state == IN_NAME); /* maybe not needed/wanted */
	    /* we should also check if parrent is varbind */
	    set_state(IN_NO_SUCH_INSTANCE); 
	    assert(*packet);
	    assert(*varbind);
	    (*varbind)->type = SNMP_TYPE_NO_SUCH_INST;
	    assert((*varbind)->value == NULL);
	    /* should be empty */
	/* varbind (- value) - end-of-mib-view */
	} else if (name && xmlStrcmp(name, BAD_CAST("end-of-mib-view")) == 0) {
	    assert(state == IN_NAME); /* maybe not needed/wanted */
	    /* we should also check if parrent is varbind */
	    set_state(IN_END_OF_MIB_VIEW); 
	    assert(*packet);
	    assert(*varbind);
	    (*varbind)->type = SNMP_TYPE_END_MIB_VIEW;
	    assert((*varbind)->value == NULL);
	    /* should be empty */
	/* varbind (- value) - value */
	} else if (name && xmlStrcmp(name, BAD_CAST("value")) == 0) {
	    assert(state == IN_NAME); /* maybe not needed/wanted */
	    /* we should also check if parrent is varbind */
	    set_state(IN_VALUE); 
	    assert(*packet);
	    assert(*varbind);
	    (*varbind)->type = SNMP_TYPE_VALUE;
	    assert((*varbind)->value == NULL);
	    /* should be empty */

	/* message */
	/* NOT FINISHED !!! */
	/* also missing msg-id, max-size, flags, security-model, usm */
	} else if (name && xmlStrcmp(name, BAD_CAST("message")) == 0) {
	    set_state(IN_MESSAGE);
	    assert((*packet));
	    /* attributes */
	    /* blen, vlen */
	    /*
	    process_snmp_attr(reader, &((*packet)->message.attr));
	    */
	} else {
	    state = IN_NONE;
	}


	break;
    case XML_READER_TYPE_TEXT:
	value = xmlTextReaderConstValue(reader);
	//xmlStrlen(value)
	//printf(" %s\n", value);
	switch (state) {
	case IN_VERSION:
	    assert(*packet);
	    if (value) {
		(*packet)->message.version.value = (int32_t)
		    strtol((char *) value, &end, 10);
		if (*end == '\0'&& (*packet)->message.version.value >=0
		    && (*packet)->message.version.value <3) {
		    (*packet)->message.version.attr.flags |= SNMP_FLAG_VALUE;
		}
	    }
	    break;
	case IN_COMMUNITY:
	    assert(*packet);
	    value = xmlTextReaderValue(reader);
	    if (value) {
		(*packet)->message.community.value = (unsigned char*)value;
		(*packet)->message.community.len = xmlStrlen(value);
		(*packet)->message.community.attr.flags |= SNMP_FLAG_VALUE;
	    }
	    break;
	case IN_ENTERPRISE:
	    assert(*packet);
	    process_snmp_oid(reader, &((*packet)->message.pdu.enterprise));
	    break;
	case IN_AGENT_ADDR:
	    assert(*packet);
	    if (value) {
		if (inet_pton(AF_INET, attr,
			      &((*packet)->message.pdu.agent_addr.value)) > 0){
		    (*packet)->message.pdu.agent_addr.attr.flags
			|= SNMP_FLAG_VALUE;
		} else {
		    if (inet_pton(AF_INET6, attr,
			      &((*packet)->message.pdu.agent_addr.value)) > 0){
			(*packet)->message.pdu.agent_addr.attr.flags
			    |= SNMP_FLAG_VALUE;
		    }
		}
	    }
	    break;
	case IN_GENERIC_TRAP:
	    assert(*packet);
	    process_snmp_int32(reader, &((*packet)->message.pdu.generic_trap));
	    break;
	case IN_SPECIFIC_TRAP:
	    assert(*packet);
	    process_snmp_int32(reader, &((*packet)->message.pdu.specific_trap));
	    break;
	case IN_TIME_STAMP:
	    assert(*packet);
	    process_snmp_int32(reader, &((*packet)->message.pdu.time_stamp));
	    break;
	case IN_REQUEST_ID:
	    assert(*packet);
	    process_snmp_int32(reader, &((*packet)->message.pdu.req_id));
	    break;
	case IN_ERROR_STATUS:
	    assert(*packet);
	    process_snmp_int32(reader, &((*packet)->message.pdu.err_status));
	    break;
	case IN_ERROR_INDEX:
	    assert(*packet);
	    process_snmp_int32(reader, &((*packet)->message.pdu.err_index));
	    break;
	/* varbind */
	case IN_NAME:
	    assert(*varbind);
	    process_snmp_oid(reader, &((*varbind)->name));
	    break;
	case IN_INTEGER32:
	    assert(*varbind);
	    assert((*varbind)->type == SNMP_TYPE_INT32);
	    process_snmp_int32(reader, (snmp_int32_t*) (*varbind)->value);
	    break;
	case IN_UNSIGNED32:
	    assert(*varbind);
	    assert((*varbind)->type == SNMP_TYPE_UINT32);
	    DEBUG("calling process_snmp_uint32() with (*varbind)->value:%x\n",
		  (*varbind)->value);
	    process_snmp_uint32(reader, (snmp_uint32_t*) (*varbind)->value);
	    break;
	case IN_UNSIGNED64:
	    assert(*varbind);
	    assert((*varbind)->type == SNMP_TYPE_UINT64);
	    process_snmp_uint64(reader, (snmp_uint64_t*) (*varbind)->value);
	    break;
	case IN_IPADDRESS:
	    assert(*varbind);
	    assert((*varbind)->type == SNMP_TYPE_IPADDR);
	    process_snmp_ipaddr(reader, (snmp_ipaddr_t*) (*varbind)->value);
	    break;
	case IN_OCTET_STRING:
	    assert(*varbind);
	    assert((*varbind)->type == SNMP_TYPE_OCTS);
	    process_snmp_octs(reader, (snmp_octs_t*) (*varbind)->value);
	    break;
	case IN_OBJECT_IDENTIFIER:
	    assert(*varbind);
	    assert((*varbind)->type == SNMP_TYPE_OID);
	    process_snmp_oid(reader, (snmp_oid_t*) (*varbind)->value);
	    break;
	}
	break;
    case XML_READER_TYPE_COMMENT:
	return;
    case XML_READER_TYPE_SIGNIFICANT_WHITESPACE:
	return;
    case XML_READER_TYPE_END_ELEMENT:
	name = xmlTextReaderConstName(reader);
	if (name == NULL)
	    name = BAD_CAST "--";
	/* packet */
	if (name && xmlStrcmp(name, BAD_CAST("packet")) == 0) {
	    // call calback function and give it filled-in packet_t object
	    DEBUG("out PACKET\n");
	    snmp_packet_free(*packet);
	}
	break;
    default:
	fprintf(stderr, "unkown xml node type: %d\n",
		xmlTextReaderNodeType(reader));
	break;
    }

    /* dump name, values */
    #ifdef debug
    name = xmlTextReaderConstName(reader);
    if (name == NULL)
        name = BAD_CAST "--";
    
    value = xmlTextReaderConstValue(reader);
    
    printf("%d %d %s %d %d", 
            xmlTextReaderDepth(reader),
	   xmlTextReaderNodeType(reader),
	   name,
	   xmlTextReaderIsEmptyElement(reader),
	   xmlTextReaderHasValue(reader));
    if (value == NULL)
        printf("\n");
    else {
        if (xmlStrlen(value) > 40)
            printf(" %.40s...\n", value);
        else
            printf(" %s\n", value);
    }
    #endif
}

static int
stream_file(char *filename)
{
    packet_t *packet = NULL;
    snmp_varbind_t *varbind = NULL;
    xmlTextReaderPtr reader;
    int i, ret;
    
    if (filename) {
	reader = xmlNewTextReaderFilename(filename);
	if (! reader) {
	    return -1;
	}
    } else {
	xmlParserInputBufferPtr input;
	
	input = xmlParserInputBufferCreateFile(stdin,
		       XML_CHAR_ENCODING_NONE);
	if (! input) {
	    return -1;
	}
	reader = xmlNewTextReader(input, NULL);
	if (! reader) {
	    xmlFreeParserInputBuffer(input);
	    return -1;
	}
    }
    
    ret = xmlTextReaderRead(reader);
    while (ret == 1) {
	process_node(reader, &packet, &varbind);
	ret = xmlTextReaderRead(reader);
    }
    xmlFreeTextReader(reader);
    if (ret != 0) {
	fprintf(stderr, "%s: xmlTextReaderRead: failed to parse '%s'\n",
		progname, filename);
	return -2;
    }

    return 0;
}

int
main(int argc, char **argv)
{
    int i;

    if (argc == 1) {
	stream_file(NULL);
    } else {
	for (i = 1; i < argc; i++) {
	    stream_file(argv[i]);
	}
    }
    
    return 0;
}
