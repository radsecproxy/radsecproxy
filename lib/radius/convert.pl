#!/usr/bin/env perl
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
#
#  Converts dictionaries to C structures.  Does not yet do "VALUE"s.
#
#  Usage: ./convert.pl dictionary ...
#
#  Reads input dictionaries, and outputs "radius.h" and "dictionaries.c"
#
#  $Id$
#
require "common.pl";

#
#  Read all of the dictionaries
#
while (@ARGV) {
    $filename = shift;
    do_file($filename);
}

#
#  For speed, the dictionary data structures have the first 256
#  attributes at fixed offsets in the array.  If the user didn't
#  define them, then we set them here to be "raw" or unknown.
#
foreach $attr_val (0..255) {
    next if defined $attributes{$attr_val};
    
    $attributes{$attr_val}{'raw'} = 1;
}

if (scalar keys %attributes == 0) {
    die "No attributes were defined\n";
}


open DICT, ">dictionaries.c" or die "Failed creating dictionaries.c: $!\n";

#
#  Print out the data structues for the vendors.
#
if (scalar keys %vendor > 0) {
    print DICT "const DICT_VENDOR nr_dict_vendors[] = {\n";
    foreach $v (sort keys %vendor) {
	print DICT "  { \n";
	print DICT "    " . $vendor{$v}{'pec'} . ", \n";
	print DICT "    " . $vendor{$v}{'type'} . ",\n";
	print DICT "    " . $vendor{$v}{'length'} . ",\n";
	print DICT "    \"" . $v, "\"\n";
	print DICT "  },\n";
    }
    print DICT "  { \n";
    print DICT "    0,\n";
    print DICT "    0,\n";
    print DICT "    0,\n";
    print DICT "    NULL\n";
    print DICT "  },\n";
    print DICT "};\n\n";
}

# needed for later.
$vendor{""}{'pec'} = 0;

sub printAttrFlag
{
    my $tmp = $attributes{$attr_val}{'flags'}{$_[0]};

    if (!$tmp) {
	$tmp = 0;
    }

    print DICT $tmp . ", ";
}

#
#  Print DICT out the attributes sorted by number.
#
my $offset = 0;
my $num_names = 0;
print DICT "const DICT_ATTR nr_dict_attrs[] = {\n";
foreach $attr_val (sort {$a <=> $b} keys %attributes) {
    print DICT "  { /* $offset */ \n";

    if (defined $attributes{$attr_val}{'raw'}) {
	print DICT "    0\n",
    } else {
	print DICT "    ", $attributes{$attr_val}{'value'}, ", \n";
	print DICT "    ", $attributes{$attr_val}{'type'}, ", \n";
	print DICT "    ", $attributes{$attr_val}{'vendor'}, ", \n";
	print DICT "    { ";
	&printAttrFlag('has_tag');
	&printAttrFlag('unknown');
#	&printAttrFlag('has_tlv');
#	&printAttrFlag('is_tlv');
	&printAttrFlag('extended');
	&printAttrFlag('extended_flags');
	&printAttrFlag('evs');
	&printAttrFlag('encrypt');
	&printAttrFlag('length');
	print DICT "},\n";
	print DICT "    \"", $attributes{$attr_val}{'name'}, "\", \n";
	$num_names++;
    }

    $attributes{$attr_val}{'offset'} = $offset++;
    
    print DICT "  },\n";
    
}
print DICT "};\n\n";

print DICT "const int nr_dict_num_attrs = ", $offset - 1, ";\n\n";
print DICT "const int nr_dict_num_names = ", $num_names - 1, ";\n\n";

my $offset = 0;
print DICT "const DICT_ATTR *nr_dict_attr_names[] = {\n";
foreach $attr_val (sort {lc($attributes{$a}{'name'}) cmp lc($attributes{$b}{'name'})} keys %attributes) {
    next if (defined $attributes{$attr_val}{'raw'});
    
    print DICT "    &nr_dict_attrs[", $attributes{$attr_val}{'offset'}, "], /* ", $attributes{$attr_val}{'name'}, " */\n";
}

print DICT "};\n\n";
close DICT;

open HDR, ">../include/radsec/radius.h" or die "Failed creating radius.c: $!\n";

print HDR "/* Automatically generated file.  Do not edit */\n\n";

foreach $v (sort keys %vendor) {
    next if ($v eq "");

    $name = $v;
    $name =~ tr/a-z/A-Z/;		# uppercase
    $name =~ tr/A-Z0-9/_/c;	# any ELSE becomes _

    print HDR "#define VENDORPEC_", $name, " ", $vendor{$v}{'pec'}, "\n";
}
print HDR "\n";

$begin_vendor = -1;
foreach $attr_val (sort {$a <=> $b} keys %attributes) {
    next if (defined $attributes{$attr_val}{'raw'});

    if ($attributes{$attr_val}{'vendor'} != $begin_vendor) {
	print HDR "\n/* ", $vendorpec{$attributes{$attr_val}{'vendor'}}, " */\n";
	$begin_vendor = $attributes{$attr_val}{'vendor'};
    }

    $name = $attributes{$attr_val}{'name'};
    $name =~ tr/a-z/A-Z/;
    $name =~ tr/A-Z0-9/_/c;

    print HDR "#define PW_", $name, " ", $attributes{$attr_val}{'value'}, "\n";
}
print HDR "\n";

print HDR "/* Fixed offsets to dictionary definitions of attributes */\n";
foreach $attr_val (sort {$a <=> $b} keys %attributes) {
    next if (defined $attributes{$attr_val}{'raw'});

    $name = $attributes{$attr_val}{'name'};
    $name =~ tr/a-z/A-Z/;
    $name =~ tr/-/_/;

    print HDR "#define RS_DA_$name (&nr_dict_attrs[$attributes{$attr_val}{'offset'}])\n";
}

print HDR "/* Automatically generated file.  Do not edit */\n";

close HDR;
