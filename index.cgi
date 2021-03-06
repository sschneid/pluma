#!/usr/bin/perl -wT

# index.cgi
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.

BEGIN { unshift @INC, './lib'; }

use strict;

eval {
    require pluma;

    my $pluma = pluma->new();

    $pluma->run();
};

if ( $@ ) { print "Content-type: text/plain\n\n$@"; }

