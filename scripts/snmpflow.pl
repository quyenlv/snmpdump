#!/usr/bin/perl

use strict;

# This script splits traces in CSV format into flows where each flow
# is recorded in a flow file which contains all CSV records for the
# flow. A flow is identified by IP addresses since management stations
# often change port numbers dynamically and devices typically only
# have a single agent. (Note that we are making some assumptions
# here!)

# To record the packets belonging to a flow, we need to maintain the
# recently seen requests so that we can match responses and reports to
# previous requests. Note that we have to deal with situations where
# we get multiple responses to a single request or where multiple
# requests lead to a single response.

# Note: We do not handle cases well where the response is received
# before the request. We decided to solve this problem only once we
# know it happens in real traces. So watch the amount of unresolved
# responses you get by running this script.

sub process {
    my $file = shift;
    my %reqs;	# recently seen requests not yet answered
    my %resp;	# seen responses for which we have no request
    my %dead;	# requests which might be purged
    open(F, "<$file") or die "$0: unable to open $file: $!\n";
    while (<F>) {
	my @a = split(/,/, $_);
	my $srcip = $a[1];
	my $srcpo = $a[2];
	my $dstip = $a[3];
	my $dstpo = $a[4];
	my $pdu   = $a[7];
	my $reqid = $a[8];
	my $key   = "$srcip-$srcpo-$dstip-$dstpo-$reqid";

	if ($pdu =~ /get-request|get-next-request|get-bulk-request|set-request/) {
	    # dst is command responder
	    my $flow = "cg-$srcip-cr-$dstip";
	    if ($reqs{$key}) { printf("ouch - overwriting request $key\n"); }
	    $reqs{$key} = $_;
	    record($flow, $_);
	} elsif ($pdu =~ /trap|trap2|inform/) {
	    # dst is notification receiver
	    my $flow = "no-$srcip-nr-$dstip";
	    if ($pdu =~ /inform/) {
		if ($reqs{$key}) { printf("ouch - overwriting request $key\n"); }
		$reqs{$key} = $_;
	    } else {
		printf("got a trap\n");
	    }
	    record($flow, $_);
	} elsif ($pdu =~ /response|report/) {
	    my $rkey  = "$dstip-$dstpo-$srcip-$srcpo-$reqid";
	    if ($reqs{$rkey}) {
		my @value = split(/,/, $reqs{$rkey});
		if ($value[7] =~ /get-request|get-next-request|get-bulk-request|set-request/) {
		    my $flow = "cg-$dstip-cr-$srcip";
		    record($flow, $_);
		} elsif ($value[7] =~ /inform/) {
		    my $flow = "no-$dstip-nr-$srcip";
		    record($flow, $_);
		} else {
		    die "got a $pdu to a $value[7] request\n";
		}
		if ($dead{$rkey}) { printf("ouch - overwriting dead $rkey\n"); }
		$dead{$rkey} = $_[0];
	    } else {
		$resp{$key} = $_;
	    }
	} else {
	    die "got unknown PDU type \"$pdu\"\n";
	}
    }
    close(F);
    printf("dead requests: %d\n", scalar(%dead));
    printf("open requests: %d\n", scalar(%reqs));
    printf("open responses: %d\n", scalar(%resp));
}

sub record {
    my $flow = shift;
    my $csv = shift;
    open(D, ">>$flow") or die "$0: unable to open $flow: $!\n";
    print D $csv;
    close(D);
}

@ARGV = ('-') unless @ARGV;
while ($ARGV = shift) {
    process($ARGV);
}
exit(0);
