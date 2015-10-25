#!/usr/bin/perl

use warnings;
use strict;

use Cwd 'abs_path';
use File::Basename;

use lib dirname(abs_path($0)).'/Net-IP-1.26/blib/lib';
use Net::IP;

use Term::ANSIColor qw(:constants);

sub printEntry2 {
	my ($color, $entry) = @_;

	chomp $entry;

	$entry =~ s/ MAC=(([a-f0-9]{2}:){11,}[a-f0-9]{2})? / /;

	if ( $entry =~ m/ SRC=([a-f0-9:]+) / ) {
		my $src = Net::IP->new($1)->short;
		$entry =~ s/ (SRC=)[a-f0-9:]+ / $1$src /;
	}

	if ( $entry =~ m/ DST=([a-f0-9:]+) / ) {
		my $src = Net::IP->new($1)->short;
		$entry =~ s/ (DST=)[a-f0-9:]+ / $1$src /;
	}

	my $first = 1;
	foreach my $e (split(/\s+/, $entry)) {
		if ( $first == 0 ) {
			print " ";
		}
		$first = 0;

		print $color;
		if (
			( $e =~ m/^\[/ ) or
			( $e =~ m/^(SRC|DST|PROTO|SPT|DPT|TYPE)=/ )
		) {
			print BOLD;
		}
		print $e;
		print RESET;
	}
	print "\n";
}

sub printEntry {
	my ($entry) = @_;

	my $rule = (split(/\s+/, $entry))[3];
	if (( ! defined $rule ) or ($rule !~ m/^\[([^\]]+)\]/ )) {
		print YELLOW $entry;
		return;
	}
	$rule = $1;

	if ( $rule =~ m/-A$/ ) {
		printEntry2(GREEN, $entry);
	}
	elsif (( $rule =~ m/-default-D$/ ) or ( $rule =~ m/-2-D$/ )) {
		printEntry2(MAGENTA, $entry);
	}
	elsif ( $rule =~ m/-[DR]$/ ) {
		printEntry2(RED, $entry);
	}
	else {
		print MAGENTA $entry;
	}

}

open (my $fh, "/var/log/messages") or die "$!: /var/log/messages";

my @lastLines;
while (my $line = <$fh>) {
	push (@lastLines, $line);
	if ( $#lastLines >= 10) {
		shift(@lastLines);
	}
}

foreach my $line (@lastLines) {
	printEntry($line);
}
undef @lastLines;

for (;;) {
	while (my $line = <$fh>) {
		
		printEntry($line);
	}

	select(undef, undef, undef, 0.1);
	seek($fh, 0, 1);
}

