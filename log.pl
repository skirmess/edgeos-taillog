#!/usr/bin/perl

use warnings;
use strict;

use Cwd 'abs_path';
use File::Basename;

use lib dirname(abs_path($0)).'/Net-IP-1.26/blib/lib';
use Net::IP;

use Term::ANSIColor qw(:constants);

use Getopt::Std;

our($opt_l, $opt_n, $opt_s);
getopts('l:ns');

my $suppressAutomaticPrinting = 0;
if ( $opt_n ) {
	$suppressAutomaticPrinting = 1;
}
my $suppressNonFirewallMessages = 0;
if ( $opt_s ) {
	$suppressNonFirewallMessages = 1;
}
my $lastLines = 10;
if ( $opt_l ) {
	$lastLines = $opt_l;
}

my @rules;
foreach my $rule (@ARGV) {
	push(@rules, $rule);
}



sub _printTraffic {
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

sub printTraffic {
	my ($action, $rule, $entry) = @_;

	if ( $action eq 'A' ) {
		_printTraffic(GREEN, $entry);
		return;
	}

	if ( $action eq 'D' ) {
		if (( $rule eq 'default' ) or ( $rule eq '2' )) {
			_printTraffic(MAGENTA, $entry);
			return;
		}
	}

	if (( $action eq 'D' ) or ( $action eq 'R' )) {
		_printTraffic(RED, $entry);
		return;
	}

	_printTraffic(CYAN, $entry);
}

sub printUnknown {
	my ($entry) = @_;

	if ( $suppressNonFirewallMessages == 0 ) {
		print YELLOW $entry;
	}
}

sub processLine {
	my ($line) = @_;
	my @tokens = split(/\s+/, $line);

	if ( $#tokens < 3 ) {
		printUnknown($line);
		return;
	}

	my %entry;

	$entry{timestamp} = shift(@tokens);
	$entry{system} = shift(@tokens);
	$entry{process} = shift(@tokens);

	if (( $entry{system} ne 'kelva' ) or ( $entry{process} ne 'kernel:' )) {
		printUnknown($line);
		return;
	}

	#
	my $t = shift(@tokens);
	if ( $t !~ m/^\[([^-]+-[^-]+(-6)?)-(default|[1-9][0-9]*)-([ADR])\]IN=(.*)/ ) {
		printUnknown($line);
		return;
	}

	$entry{rulebase} = $1;
	$entry{rule} = $3;
	$entry{action} = $4;
	$entry{interface_in} = $5;

	foreach $t (@tokens) {
		if ( $t =~ m/^PROTO=(.*)$/ ) {
			$entry{proto} = $1;
			last;
		}
	}

	foreach $t (@tokens) {
		if ( $t =~ m/^SPT=(.*)$/ ) {
			$entry{spt} = $1;
			last;
		}
	}

	foreach $t (@tokens) {
		if ( $t =~ m/^DPT=(.*)$/ ) {
			$entry{dpt} = $1;
			last;
		}
	}

	foreach $t (@tokens) {
		if ( $t =~ m/^SRC=(.*)$/ ) {
			$entry{src} = $1;

			if ( $entry{src} =~ m/^[a-f0-9:]+$/ ) {
				$entry{src} = Net::IP->new($entry{src})->short;
			}
			last;
		}
	}

	foreach $t (@tokens) {
		if ( $t =~ m/^DST=(.*)$/ ) {
			$entry{dst} = $1;

			if ( $entry{dst} =~ m/^[a-f0-9:]+$/ ) {
				$entry{dst} = Net::IP->new($entry{dst})->short;
			}
			last;
		}
	}

	foreach $t (@tokens) {
		if ( $t =~ m/^TYPE=(.*)$/ ) {
			$entry{type} = $1;
			last;
		}
	}

	my $print = 1;
	foreach my $rule (@rules) {
		my @rule = split(/\s+/, $rule);

		if ( $rule[0] eq 'from' ) {
			shift(@rule);

			if ( $rule[0] eq 'zone' ) {
				shift(@rule);
				my $z = shift(@rule);

				if ( $entry{rulebase} !~ m/^${z}-/ ) {
					# no match;
					next;
				}
			}
			else {
				die;
			}
		}

		if ( $rule[0] eq 'to' ) {
			shift(@rule);

			if ( $rule[0] eq 'zone' ) {
				shift(@rule);
				my $z = shift(@rule);

				if ( $entry{rulebase} !~ m/-${z}(-6)?$/ ) {
					# no match
					next;
				}
			}
			else {
				die;
			}
		}

		if ( $rule[0] eq 'proto' ) {
			shift(@rule);

			if (! defined $entry{proto}) {
				# no match
				next;
			}

			if ( lc($rule[0]) ne lc($entry{proto}) ) {
				# no match
				next;
			}

			shift(@rule);

			if (( defined $rule[0] ) && ( $rule[0] eq 'type' )) {
				shift(@rule);

				if ( ! defined $entry{type} ) {
					# no match
					next;
				}

				if ( lc($rule[0]) ne lc ($entry{type}) ) {
					# no match
					next;
				}

				shift(@rule);
			}
		}

		if ( $rule[0] eq 'source' ) {
			shift(@rule);

			if ( $rule[0] eq 'port' ) {
				shift(@rule);

				if ( ! defined $entry{spt} ) {
					# no match
					next;
				}

				if ( $rule[0] ne $entry{spt} ) {
					# no match
					next;
				}

				shift(@rule);
			}

			if ( $rule[0] eq 'host' ) {
				shift(@rule);

				if ( ! defined $entry{src} ) {
					# no match
					next;
				}

				my $x = shift(@rule);
				if ( $x =~ m/^[a-f0-9:]+$/ ) {
					$x = Net::IP->new($x)->short;
				}

				if ( $x ne $entry{src} ) {
					# no match
					next;
				}
			}
		}

		if ( $rule[0] eq 'destination' ) {
			shift(@rule);

			if ( $rule[0] eq 'port' ) {
				shift(@rule);

				if ( ! defined $entry{dpt} ) {
					# no match
					next;
				}

				if ( $rule[0] ne $entry{dpt} ) {
					# no match
					next;
				}

				shift(@rule);
			}

			if ( $rule[0] eq 'host' ) {
				shift(@rule);

				if ( ! defined $entry{dst} ) {
					# no match
					next;
				}

				my $x = shift(@rule);
				if ( $x =~ m/^[a-f0-9:]+$/ ) {
					my $x = Net::IP->new($x)->short;
				}

				if ( $x ne $entry{dst} ) {
					# no match
					next;
				}
			}
		}

		if ( $rule[0] eq 'rule' ) {
			shift(@rule);

			if ( ! defined $entry{rule} ) {
				# no match
				next;
			}

			if ( $rule[0] ne $entry{rule} ) {
				# no match
				next;
			}

			shift(@rule);
		}

		if ( $rule[0] eq 'prune' ) {
			shift(@rule);
			$print = 0;
		}
		elsif ( $rule[0] eq 'print' ) {
			shift(@rule);
			if ( $print == 1 ) {
				$print = 2;
			}
		}

		if ( $#rule != -1 ) {
			die "cannot parse rule: $rule >>> $rule[0] <<<";
		}
	}

	if (
		(( $suppressAutomaticPrinting == 0 ) and ( $print !=0 )) or
		(( $suppressAutomaticPrinting != 0 ) and ( $print == 2 )) ) {
		printTraffic($entry{action}, $entry{rule}, $line);
	}
}

open (my $fh, "/var/log/messages") or die "$!: /var/log/messages";

my @lastLines;
while (my $line = <$fh>) {
	push (@lastLines, $line);
	if ( $#lastLines >= $lastLines) {
		shift(@lastLines);
	}
}

foreach my $line (@lastLines) {
	processLine($line);
}
undef @lastLines;

for (;;) {
	while (my $line = <$fh>) {

		processLine($line);
	}

	select(undef, undef, undef, 0.1);
	seek($fh, 0, 1);
}

