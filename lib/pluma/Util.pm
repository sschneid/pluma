# pluma::Util
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
# $Id: Util.pm,v 1.1.1.1 2008/07/28 17:58:46 sschneid Exp $

package pluma::Util;

@ISA = qw( pluma );

use strict;
use warnings;

sub new { return bless {}, shift; }

sub readConfig {
    my $self = shift;

    my ( $arg );
    %{$arg} = @_;

    my ( $config );

    $arg->{'configFile'} || return( 0 );

    if ( -e $arg->{'configFile'} ) {
        open configFile, $arg->{'configFile'} || return( 0 );

        while( <configFile> ) {
            $config->{$1} = $2 if /^\$(.+?):.+?"(.+?)"/;
            ( @{$config->{$1}} ) = split / /, $2 if /^\@(.+?):.+?"(.+?)"/;
        }
        close configFile;
    }
    else {
        return( 0 );
    }

    map { $config->{$_} =~ s/\$([\w.]+)/$config->{$1}/g; } keys %{$config};

    return( $config );
}

sub untaintCGI {
    my $self = shift;

    my ( $arg );
    %{$arg} = @_;

    my ( $taint, $untaint );

    map {
        my @a = $arg->{'cgi'}->param( $_ );
        if ( ( scalar @a ) > 1 ) {
            $taint->{$_} = [ $arg->{'cgi'}->param( $_ ) ];
        }
        else {
            $taint->{$_} =   $arg->{'cgi'}->param( $_ );
        }
    } @{ $arg->{'cgi'}->{'.parameters'} };

    map {
        s/"/\\"/g;
        s/'/\\'/g;
        $untaint->{$_} = $taint->{$_}
            if /^[\w\d\-\.\!\@\?\s~,<>()=\+_\''"&\[\]]+$/;
    } keys %{$taint};

    return( $untaint );
}

1;
