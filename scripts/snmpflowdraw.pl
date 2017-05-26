#!/usr/bin/perl
#
# This script draws the flow chart between SNMP Manager and
# SNMP Agent in the trace. The script only becomes useful
# if MIB information (see -m option) is passed to it.
#
# To run this script:
#    snmpflowdraw.pl [-m MIB_file] [<filename>]
#
# (c) 2017 Quyen Le Van <gaimande@gmail.com>
#
# 

use Getopt::Std;
use strict;

my %oid_name;		# oid to name mapping
my %oid_module;		# oid to module mapping
my %SNMP_METHOD = (
		'set-request' => " SET REQ ",
		'get-request' => " GET REQ ",
		'get-next-request' => " GET NEXT REQ ",
		'get-bulk-request' => " GET BULK REQ ",
		'response' => " RESPONSE ",
		'trap2' => " TRAP ",
		'snmpV2-trap' => " TRAP ",
		'inform' => " INFORM ",
		'inform-request' => " INFORM REQ ",
		'report' => " REPORT ",
	);

my $WIDTH_VIEW = 90; # The length of information
my $TAB_VIEW = 4;    # The length of space at the beginning of line
my $IP_MAX_LEN = length("255.255.255.255");

#
# Return $str centered in a field of $col $padchars.
# $padchar defaults to ' ' if not specified.
# $str is truncated to len $column if too long.
#
sub pad
{
    my ($str, $col, $padchar) = @_;
    $padchar = ' ' unless $padchar;
    my $strlen = length($str);
    $str = substr($str, 0, $col) if ($strlen > $col);
    my $fore = int(($col - $strlen) / 2);
    my $aft = $col - ($strlen + $fore);
    $padchar x $fore . $str . $padchar x $aft;
}

#
# Load MIB information from the file passed as argument. The
# file has to be in 'smidump -f identifiers' format.
#
sub load_mib {
    my $file = shift;
    open(F, "<$file") or die "Can't open $file: $!";
    while(<F>) {
	my @a = split;
	if ($a[2] =~ /scalar|column|notification/) {
	    $oid_name{$a[3]} = $a[1];
	    $oid_module{$a[3]} = $a[0];
	}
    }
    close(F);
    print STDERR "loaded ".keys(%oid_name)." oids from file $file\n";
}

#
#
#
sub process {
    my $file = shift;
	my ($info, $oid, $type, $value, $snmp_mgr, $snmp_agt);

    if ($file =~ /\.g|Gz|Z$/)
	{
		open(infile, "zcat $file |") or die "$0: Cannot open $file: $!\n"
    }
	else
	{
		open(infile, "<$file") or die "$0: Cannot open $file: $!\n";
    }

    while (<infile>)
	{
		my @a = split(/,/, $_);
		my $op = $a[7];
		my $nvbs = $a[11];
		my $sender = $a[1];
		my $sign;

		if (!$snmp_mgr)
		{
			if ($op =~ /trap|response/)
			{
				$snmp_mgr = $a[3];
				$snmp_agt = $a[1];
			}
			else
			{
				$snmp_mgr = $a[1];
				$snmp_agt = $a[3];

			}

			my $width = $WIDTH_VIEW + 2*$TAB_VIEW - $IP_MAX_LEN;
			printf "%-${IP_MAX_LEN}s  %${width}s\n", "SNMP Manager", "SNMP Agent";
			printf "%-${IP_MAX_LEN}s  %${width}s\n", $snmp_mgr, $snmp_agt;
		}

		for (my $i = 0; $i < $nvbs; $i++)
		{
			$info = $oid = $a[12 + 3*$i];
			$type = $a[13 + 3*$i];
			($value = $a[14 + 3*$i]) =~ s/\R//g;

			while(! $oid_name{$oid} && $oid =~ s/(.*)\.\d+$/$1/){};

			$info .= " ($oid_name{$oid})" if $oid_name{$oid};
			
			if ($type eq "octet-string")
			{
				# Convert HEX to string
				$value =~ s/([a-fA-F0-9][a-fA-F0-9])/chr(hex($1))/eg;

				# Remove all NULL character
				$value =~ s/\x0+$// if $type eq "octet-string";

				$value = length $value ? "\"$value\"" : "(null)";
			}
		
			if ($op eq "response" && $value eq "")
			{
				$info .= " = $type";
			}
			elsif ($op ne "get-request")
			{
				$info .= " = $value";
			}

			# Remove trailing feed new line
			$info =~ s/\R//g;

			$info = substr ($info, 0, $WIDTH_VIEW - 3)."..." if length($info) > $WIDTH_VIEW;

			print " " x $TAB_VIEW, "|", pad($info, $WIDTH_VIEW), "|\n";
		}

		$sign = ($op =~ /trap/) ? "=" : "-";

		if ($sender == $snmp_mgr)
		{
			    print " " x $TAB_VIEW, "|", pad($SNMP_METHOD{$op}, $WIDTH_VIEW - 1, $sign), ">|\n";
		}
		else
		{
			    print " " x $TAB_VIEW, "|<", pad($SNMP_METHOD{$op}, $WIDTH_VIEW - 1, $sign), "|\n";

		}

		print " " x $TAB_VIEW, "|", pad(" ", $WIDTH_VIEW), "|\n";

    }
    close(infile);
}

#
# Print usage information about this program.
#
sub usage()
{
     print STDERR << "EOF";
Usage: $0 [-h] [-m mibfile] [files|-]
      
This program draw flow chart between SNMP Manager and SNMP Agent from SNMP trace files in CSV format.
	
  -h         display this (help) message
  -m mibfile file with MIB information (in smidump -f identifiers format)
EOF
     exit;
}

# Here is where the script basically begins. Parse the command line
# arguments and then process all files on the commandline in turn.
my %opt;
getopts( "m:h", \%opt ) or usage();
usage() if defined $opt{h};
load_mib($opt{m}) if defined $opt{m};

@ARGV = ('-') unless @ARGV;
while ($ARGV = shift)
{
    process($ARGV);
}

exit(0);
