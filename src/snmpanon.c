/*
 * snmpanon.c --
 *
 * A utility to anonymize SNMP messages in XML format (as generated by
 * snmpdump). The anonymized XML output will be written to stdout.
 *
 * (c) 2004-2005 Juergen Schoenwaelder <j.schoenwaelder@iu-bremen.de>
 *
 */

#include "config.h"

#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#include <libxml/xmlmemory.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>

#include <smi.h>

#include "xpath-filter.h"
#include "libanon.h"

static const char *progname = "snmpanon";

static xmlDocPtr xml_doc;

static unsigned char my_key[32] = 
{
     21, 34, 23,141, 51,164,207,128, 19, 10, 91, 22, 73,144,125, 16,
    216,152,143,131,121,121,101, 39, 98, 87, 76, 45, 42,132, 34,  2
};



/*
 *
 */

static void
mark_anon_ip_node(anon_ip_t *an_ip, const char *xpath, xmlXPathContextPtr ctxt)
{
    xmlXPathObjectPtr obj;
    xmlChar *content;
    int i;
    in_addr_t ip;

    obj = xmlXPathEval(BAD_CAST(xpath), ctxt);
    if (obj) {
	if (obj->type == XPATH_NODESET) {
	    for (i = 0; i < xmlXPathNodeSetGetLength(obj->nodesetval); i++) {
		content = xmlNodeGetContent(obj->nodesetval->nodeTab[i]);
		if (inet_pton(AF_INET, (char *) content, &ip) > 0) {
		    anon_ip_set_used(an_ip, ip, 32);
		}
	    }
	}
	xmlXPathFreeObject(obj);
    }
}

static void
repl_anon_ip_node(anon_ip_t *an_ip, const char *xpath, xmlXPathContextPtr ctxt)
{
    xmlXPathObjectPtr obj;
    xmlChar *content;
    int i;
    in_addr_t ip;
    in_addr_t aip;

    obj = xmlXPathEval(BAD_CAST(xpath), ctxt);
    if (obj) {
	if (obj->type == XPATH_NODESET) {
	    for (i = 0; i < xmlXPathNodeSetGetLength(obj->nodesetval); i++) {
		content = xmlNodeGetContent(obj->nodesetval->nodeTab[i]);
		if (inet_pton(AF_INET, (char *) content, &ip) > 0) {
		    char buf[INET_ADDRSTRLEN];
		    (void) anon_ip_map_pref_lex(an_ip, ip, &aip);
		    if (inet_ntop(AF_INET, &aip, buf, sizeof(buf))) {
			xmlNodeSetContent(obj->nodesetval->nodeTab[i],
					  BAD_CAST(buf));
		    }
		}
	    }
	}
	xmlXPathFreeObject(obj);
    }
}

/*
 *
 */

static void
mark_anon_port_node(anon_int64_t *an_ip, const char *xpath, xmlXPathContextPtr ctxt)
{
    xmlXPathObjectPtr obj;
    xmlChar *content;
    int i;
    int64_t num;

    obj = xmlXPathEval(BAD_CAST(xpath), ctxt);
    if (obj) {
	if (obj->type == XPATH_NODESET) {
	    for (i = 0; i < xmlXPathNodeSetGetLength(obj->nodesetval); i++) {
		content = xmlNodeGetContent(obj->nodesetval->nodeTab[i]);
		if (sscanf((char *)content, "%"SCNd64, &num) == 1) {
		    anon_int64_set_used(an_ip, num);
		}
	    }
	}
	xmlXPathFreeObject(obj);
    }
}

static void
repl_anon_port_node(anon_int64_t *an_ip, const char *xpath, xmlXPathContextPtr ctxt)
{
    xmlXPathObjectPtr obj;
    xmlChar *content;
    int i;
    int64_t num, anum;

    obj = xmlXPathEval(BAD_CAST(xpath), ctxt);
    if (obj) {
	if (obj->type == XPATH_NODESET) {
	    for (i = 0; i < xmlXPathNodeSetGetLength(obj->nodesetval); i++) {
		content = xmlNodeGetContent(obj->nodesetval->nodeTab[i]);
                if (sscanf((char *)content, "%"SCNd64, &num) == 1) {
		    char buf[40];
		    (void) anon_int64_map_lex(an_ip, num, &anum);
		    if (snprintf(buf, sizeof(buf), "%"PRId64, anum) > 0) {
			xmlNodeSetContent(obj->nodesetval->nodeTab[i],
					  BAD_CAST(buf));
		    }
		}
	    }
	}
	xmlXPathFreeObject(obj);
    }
}

static void
mark_anon_varbind_name(const char *xpath, xmlXPathContextPtr ctxt)
{
    xmlXPathObjectPtr obj;
    xmlChar *content;
    SmiNode *smiNode;
    SmiType *smiType;
    int i;

    obj = xmlXPathEval(BAD_CAST(xpath), ctxt);
    if (obj) {
	if (obj->type == XPATH_NODESET) {
	    for (i = 0; i < xmlXPathNodeSetGetLength(obj->nodesetval); i++) {
		content = xmlNodeGetContent(obj->nodesetval->nodeTab[i]);
		fprintf(stderr, "** <%s>\n", (char *) content);
		smiNode = smiGetNode(NULL, (char *) content);
		if (smiNode) {
		    fprintf(stdout, "** %s", smiNode->name);
		    smiType = smiGetNodeType(smiNode);
		    if (smiType) {
			fprintf(stdout, " [%s]", smiType->name);
		    }
		    fprintf(stdout, "\n");
		}
	    }
	}
	xmlXPathFreeObject(obj);
    }
}

/*
 * First anonymization transformation pass: collect all the data
 * values that need anonymization and clear the rest.
 */

static void
anon_pass1(anon_ip_t *an_ip, anon_int64_t *an_port)
{
    xmlXPathContextPtr ctxt;

    ctxt = xmlXPathNewContext(xml_doc);
    ctxt->node = xmlDocGetRootElement(xml_doc);

    mark_anon_ip_node(an_ip, "//snmptrace/packet/*/@ip", ctxt);
    mark_anon_port_node(an_port, "//snmptrace/packet/*/@port", ctxt);

    mark_anon_varbind_name("//snmptrace/packet/snmp/*/variable-bindings/varbind/name", ctxt);

    xmlXPathFreeContext(ctxt);
}

/*
 * Second anonymization transformation pass: replace the data
 * looking for anonymization.
 */

static void
anon_pass2(anon_ip_t *an_ip, anon_int64_t *an_port)
{
    xmlXPathContextPtr ctxt;

    ctxt = xmlXPathNewContext(xml_doc);
    ctxt->node = xmlDocGetRootElement(xml_doc);

    repl_anon_ip_node(an_ip, "//snmptrace/packet/*/@ip", ctxt);
    repl_anon_port_node(an_port, "//snmptrace/packet/*/@port", ctxt);
    
    xmlXPathFreeContext(ctxt);
}


int
main(int argc, char **argv)
{
    int i, c;
    char buffer[1024];
    char *filter = NULL;
    xpath_filter_t *xpf;

    xpf = xpath_filter_new();

    for (i = 1; i < argc; i++)
	if ((strstr(argv[i], "-s") == argv[i]) ||
	    (strstr(argv[i], "--smi-config") == argv[i])) break;
    if (i == argc) {
	smiInit("smilint");
    } else {
	smiInit(NULL);
    }
	
    while ((c = getopt(argc, argv, "Vhc:d:m:")) != -1) {
	switch (c) {
	case 'c':
	    if (xpf) {
		xpath_filter_add(xpf, BAD_CAST(optarg),
				 XPATH_FILTER_TYPE_CLEAR);
	    }
	    break;
	case 'd':
	    if (xpf) {
		xpath_filter_add(xpf, BAD_CAST(optarg),
				 XPATH_FILTER_TYPE_DELETE);
	    }
	    break;
	case 'm':
	    smiLoadModule(optarg);
	    break;
	case 's':
	    smiReadConfig(optarg, "snmpdump");
	    break;
	case 'V':
	    printf("%s %s\n", progname, VERSION);
	    exit(0);
	case 'h':
	case '?':
	    printf("%s [-c xpath] [-d xpath] [-m module] [-h] [-s config] file ... \n", progname);
	    exit(0);
	}
    }

    for (i = 1; i < argc; i++) {
	xml_doc = xmlReadFile(argv[i], NULL, 0);
	if (! xml_doc) {
	    fprintf(stderr, "%s: could not parse XML file '%s'\n",
		    progname, argv[i]);
	    continue;
	}

	/* anonymize the data */
	
	anon_ip_t *an_ip;
	anon_int64_t *an_port;

	xmlXPathInit();

	an_ip = anon_ip_new();
	if (! an_ip) {
	    fprintf(stderr, "%s: initialization of IP anonymization failed\n",
		    progname);
	    exit(1);
	}
	an_port = anon_int64_new(0, 65535);
	if (! an_port) {
	    fprintf(stderr, "%s: initialization of port anonymization failed\n",
		    progname);
	    exit(1);
	}
	
	anon_ip_set_key(an_ip, my_key);
	anon_int64_set_key(an_port, my_key);

	anon_pass1(an_ip, an_port);	/* xml_root passed as global */
	anon_pass2(an_ip, an_port);	/* xml_root passed as global */

	anon_ip_delete(an_ip);
	anon_int64_delete(an_port);

	/* apply the filters */
	
	xpath_filter_apply(xpf, xml_doc);

	/* print the resulting xml document */

	if (xmlDocFormatDump(stdout, xml_doc, 1) == -1) {
	    fprintf(stderr, "%s: failed to serialize xml document\n", progname);
	    exit(1);
	}
    }
    
    /* cleanup */

    xpath_filter_delete(xpf);
}