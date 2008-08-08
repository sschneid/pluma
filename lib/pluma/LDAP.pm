# pluma::LDAP
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
# $Id: LDAP.pm,v 1.1.1.1 2008/07/28 17:58:46 sschneid Exp $

package pluma::LDAP;

use Net::LDAP;

use strict;
use warnings;

sub new {
    my $self = bless {}, shift;

    my ( $arg );
    %{$arg} = @_;

    my $ldap = $self->connect(
        server => $arg->{'server'},
        SSL    => $arg->{'SSL'}
    )
    || return( 0 );

    return( $self );
}

sub bind {
    my $self = shift;

    my ( $arg );
    %{$arg} = @_;

    my $err = $self->{'ldap'}->bind(
        $arg->{'bindDN'}, password => $arg->{'password'}
    );

    if ( $err->code() ) { return( 0 ); } else { return( 1 ); }
}

sub connect {
    my $self = shift;

    my ( $arg );
    %{$arg} = @_;

    $arg->{'server'} = 'ldaps://' . $arg->{'server'} . ':636' if $arg->{'SSL'};

    $self->{'ldap'} = Net::LDAP->new( $arg->{'server'} )
    || return( 0 );

    return( 1 );
}

sub fetch {
    my $self = shift;

    my ( $arg );
    %{$arg} = @_;

    my ( $r );

    my $result = $self->{'ldap'}->search(
        base   => $arg->{'base'},
        filter => $arg->{'filter'},
        attrs  => $arg->{'attrs'},

        sizelimit => $self->{'config'}->{'fetch.Limit.Size'},
        timelimit => $self->{'config'}->{'fetch.Limit.Time'}
    );

    # Error if single entry not found
    return( 0 ) unless $result->entries();

    foreach my $entry ( $result->all_entries() ) {
        foreach my $attr ( $entry->attributes ) {
            my $val = [ $entry->get_value( $attr ) ];
            $r->{$entry->dn()}->{$attr} = @{$val} > 1 ? $val : $val->[0];
        }
    }

    # Flatten single-key hashes
    if ( keys %{$r} == 1 ) {
        foreach my $key ( keys %{$r} ) {
            $r = $r->{$key};
        }
    }

    return( $r );
}

sub add { return shift->{'ldap'}->add( @_ ); }

sub delete { return shift->{'ldap'}->delete( @_ ); }

sub modify { return shift->{'ldap'}->modify( @_ ); }

1;
