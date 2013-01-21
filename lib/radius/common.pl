######################################################################
# Copyright (c) 2011, Network RADIUS SARL
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the <organization> nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
######################################################################
our %attributes;
our %vendor;
our %vendorpec;
our $begin_vendor = 0;

$vendorpec{'0'} = "IETF";

sub do_file()
{
    my $filename = shift;
    my $fh;

    $dir = $filename;
    $dir =~ s:/[^/]+?$::;
    $lineno = 0;

    open $fh, "<$filename" or die "Failed to open $filename: $!\n";

    while (<$fh>) {
	$lineno++;
	next if (/^\s*#/);
	next if (/^\s*$/);
	s/#.*//;
	s/\s+$//;

	next if ($_ eq "");

	#
	#  Remember the vendor
	#
	if (/^VENDOR\s+([\w-]+)\s+(\w+)(.*)/) {
	    my $me = $1;

	    $vendor{$me}{'pec'} = $2;
	    $vendorpec{$2} = $me;

	    $vendor{$me}{'type'} = 1;
	    $vendor{$me}{'length'} = 1;

	    if ($3) {
		$format=$3;
		$format =~ s/^\s+//;

		if ($format !~ /^format=(\d+),(\d+)$/) {
		    die "Unknown format $format\n";
		}
		$vendor{$me}{'type'} = $1;
		$vendor{$me}{'length'} = $2;
	    }
	    next;
	}

	#
	#  Remember if we did begin-vendor.
	#
	if (/^BEGIN-VENDOR\s+([\w-]+)/) {
	    if (!defined $vendor{$1}) {
		die "Unknown vendor $1\n";
	    }
	    $begin_vendor = $vendor{$1}{'pec'};
	    next;
	}

	#
	#  Remember if we did this.
	#
	if (/^END-VENDOR/) {
	    $begin_vendor = 0;
	    next;
	}

	#
	#  Get attribute.
	#
	if (/^ATTRIBUTE\s+([\w-\/.]+)\s+(\w+)\s+(\w+)(.*)/) {
	    $name=$1;
	    $value = $2;
	    $type = $3;
	    $stuff = $4;

	    $value =~ tr/[A-F]/[a-f]/; # normal form for hex
	    $value =~ tr/X/x/;

	    if ($value =~ /^0x/) {
		$index = hex $value;
	    } else {
		$index = $value;
	    }

	    next if (($begin_vendor == 0) && ($index > 255));

	    $index += ($begin_vendor << 16);

	    $attributes{$index}{'name'} = $name;
	    $attributes{$index}{'value'} = $value;
	    if ($begin_vendor ne "") {
		$attributes{$index}{'vendor'} = $begin_vendor;
	    }

	    $type =~ tr/a-z/A-Z/;
	    $attributes{$index}{'type'} = "RS_TYPE_$type";

	    $stuff =~ s/^\s*//;

	    if ($stuff) {
		foreach $text (split /,/, $stuff) {
		    if ($text eq "encrypt=1") {
			$attributes{$index}{'flags'}{'encrypt'} = "FLAG_ENCRYPT_USER_PASSWORD";
		    } elsif ($text eq "encrypt=2") {
			$attributes{$index}{'flags'}{'encrypt'} = "FLAG_ENCRYPT_TUNNEL_PASSWORD";

			} elsif ($text eq "encrypt=3") {
			$attributes{$index}{'flags'}{'encrypt'} = "FLAG_ENCRYPT_ASCEND_SECRET";

		    } elsif ($text eq "has_tag") {
			$attributes{$index}{'flags'}{'has_tag'} = "1";

		    } elsif ($text =~ /\[(\d+)\]/) {
			$attributes{$index}{'flags'}{'length'} = $1;
			
		    } else {
			die "$filename: $lineno - Unknown flag $text\n";
		    }
		}
	    }

	    if ($type eq "BYTE") {
		$attributes{$index}{'flags'}{'length'} = "1";
		
	    } elsif ($type eq "SHORT") {
		$attributes{$index}{'flags'}{'length'} = "2";
		
	    } elsif ($type eq "INTEGER") {
		$attributes{$index}{'flags'}{'length'} = "4";
		
	    } elsif ($type eq "IPADDR") {
		$attributes{$index}{'flags'}{'length'} = "4";
		
	    } elsif ($type eq "DATE") {
		$attributes{$index}{'flags'}{'length'} = "4";
		
	    } elsif ($type eq "IFID") {
		$attributes{$index}{'flags'}{'length'} = "8";
		
	    } elsif ($type eq "IPV6ADDR") {
		
		$attributes{$index}{'flags'}{'length'} = "16";
	    }

	    $name2val{$name} = $index;
	    next;
	}

	#
	#  Values.
	#
	if (/^VALUE\s+([\d\w-\/.]+)\s+([\w-\/,.+]+)\s+(\w+)(.*)/) {
	    next;

	    $attr = $1;
	    $name = $2;
	    $value = $3;
	    $stuff = $d;

	    $value =~ tr/[A-F]/[a-f]/; # normal form for hex
	    $value =~ tr/X/x/;

	    if ($value =~ /^0x/) {
		$index = hex $value;
	    } else {
		$index = $value;
	    }

	    if (!defined $name2val{$attr}) {
		print "# FIXME: FORWARD REF?\nVALUE $attr $name $value$stuff\n";
		next;
	    }

	    $values{$name2val{$attr}}{$index} = "$attr $name $value$stuff";
	    next;
	}

	if (/^\$INCLUDE\s+(.*)$/) {
	    do_file("$dir/$1");
	    next;
	}

	die "unknown text in line $lineno of $filename: $_\n";
    }

    close $fh;
}

1;
