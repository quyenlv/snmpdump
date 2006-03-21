/*
 * snmpdump.c --
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
#include <unistd.h>
#include <regex.h>

static const char *progname = "snmpdump";

typedef enum {
    INPUT_XML = 1,
    INPUT_PCAP = 2
} input_t;

typedef enum {
    OUTPUT_XML = 1,
    OUTPUT_CSV = 2
} output_t;


static snmp_filter_t *del_filter = NULL;
static snmp_filter_t *clr_filter = NULL;



static void
print_xml(snmp_packet_t *pkt, void *user_data)
{
    FILE *stream = (FILE *) user_data;
    
    assert(pkt && user_data);
    
    snmp_xml_write_stream(stream, pkt);
}


static void
print_csv(snmp_packet_t *pkt, void *user_data)
{
    FILE *stream = (FILE *) user_data;

    assert(pkt && user_data);

    snmp_csv_write_stream(stream, pkt);
}



/*
 * The main function to parse arguments, initialize the libraries and
 * to fire off the libnids library using nids_run() for every input
 * file we process.
 */

int
main(int argc, char **argv)
{
    int i, c;
    char *expr = NULL;
    output_t output = OUTPUT_XML;
    input_t input = INPUT_PCAP;
    char *errmsg;

    while ((c = getopt(argc, argv, "Vc:d:f:i:o:h")) != -1) {
	switch (c) {
	case 'c':
	    clr_filter = snmp_filter_new(optarg, &errmsg);
	    if (! clr_filter) {
		fprintf(stderr, "%s: ignoring clear filter: %s\n",
			progname, errmsg);
		continue;
	    }
	    break;
	case 'd':
	    del_filter = snmp_filter_new(optarg, &errmsg);
	    if (! del_filter) {
		fprintf(stderr, "%s: ignoring delete filter: %s\n",
			progname, errmsg);
		continue;
	    }
	    break;
	case 'i':
	    if (strcmp(optarg, "pcap") == 0) {
		input = INPUT_PCAP;
	    } else if (strcmp(optarg, "xml") == 0) {
		input = INPUT_XML;
	    } else {
		fprintf(stderr, "%s: ignoring input format: %s unknown\n",
			progname, optarg);
	    }
	    break;
	case 'o':
	    if (strcmp(optarg, "csv") == 0) {
		output = OUTPUT_CSV;
	    } else if (strcmp(optarg, "xml") == 0) {
		output = OUTPUT_XML;
	    } else {
		fprintf(stderr, "%s: ignoring output format: %s unknown\n",
			progname, optarg);
	    }
	    break;
	case 'f':
	    expr = optarg;
	    break;
	case 'V':
	    printf("%s %s\n", progname, VERSION);
	    exit(0);
	case 'h':
	case '?':
	    printf("%s [-c regex] [-d regex] [-f filter] [-i format] [-o format] [-h] file ... \n", progname);
	    exit(0);
	}
    }

    switch (output) {
    case OUTPUT_XML:
	snmp_xml_write_stream_begin(stdout);
	for (i = optind; i < argc; i++) {
	    switch (input) {
	    case INPUT_XML:
#if 0
		snmp_xml_read_file(argv[i], print_xml, stdout);
#endif
		break;
	    case INPUT_PCAP:
		snmp_pcap_read_file(argv[i], expr, print_xml, stdout);
		break;
	    }
	}
	snmp_xml_write_stream_end(stdout);
	break;
    case OUTPUT_CSV:
	snmp_csv_write_stream_begin(stdout);
	for (i = optind; i < argc; i++) {
	    switch (input) {
	    case INPUT_XML:
#if 0
		snmp_xml_read_file(argv[i], print_csv, stdout);
#endif
		break;
	    case INPUT_PCAP:
		snmp_pcap_read_file(argv[i], expr, print_csv, stdout);
		break;
	    }
	}
	snmp_csv_write_stream_end(stdout);
	break;
    }

    if (clr_filter) {
	snmp_filter_delete(clr_filter);
    }

    if (del_filter) {
	snmp_filter_delete(del_filter);
    }

    return 0;
}
