#!/usr/local/bin/perl -wT

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
#
# $Id: index.cgi,v 1.2 2008/08/18 14:17:54 sschneid Exp $

BEGIN { unshift @INC, './lib'; }

use strict;

eval {
    require pluma;

    my $pluma = pluma->new(
        tmpl_path => 'thtml/'
    );

    $pluma->run();
};

if ( $@ ) { print "Content-type: text/plain\n\n$@"; }

