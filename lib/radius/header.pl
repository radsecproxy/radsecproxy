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
#  Converts dictionaries to C defines.  Does not yet do "VALUE"s.
#
#  $Id$
#
require "common.pl";

while (@ARGV) {
    $filename = shift;
    do_file($filename);
}


print "/* Automatically generated file.  Do not edit */\n\n";

foreach $v (sort keys %vendor) {
    $name = $v;
    $name =~ tr/a-z/A-Z/;		# uppercase
    $name =~ tr/A-Z0-9/_/c;	# any ELSE becomes _

    print "#define VENDORPEC_", $name, " ", $vendor{$v}{'pec'}, "\n";
}
print "\n";

$begin_vendor = -1;
foreach $attr_val (sort {$a <=> $b} keys %attributes) {
    if ($attributes{$attr_val}{'vendor'} != $begin_vendor) {
	print "\n/* ", $vendorpec{$attributes{$attr_val}{'vendor'}}, " */\n";
	$begin_vendor = $attributes{$attr_val}{'vendor'};
    }

    $name = $attributes{$attr_val}{'name'};
    $name =~ tr/a-z/A-Z/;
    $name =~ tr/A-Z0-9/_/c;

    print "#define PW_", $name, " ", $attributes{$attr_val}{'value'}, "\n";
}
print "\n\n";

print "/* Automatically generated file.  Do not edit */\n";

