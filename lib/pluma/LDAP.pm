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

    $arg->{'base'} = [ $arg->{'base'} ] unless ref $arg->{'base'};

    my ( $r );

    foreach my $base ( @{$arg->{'base'}} ) {
        my $result = $self->{'ldap'}->search(
            base   => $base,
            filter => $arg->{'filter'},
            attrs  => $arg->{'attrs'},

            sizelimit => $self->{'config'}->{'fetch.Limit.Size'},
            timelimit => $self->{'config'}->{'fetch.Limit.Time'}
        );

        next unless $result->entries();

        foreach my $entry ( $result->all_entries() ) {
            foreach my $attr ( $entry->attributes ) {
                my $val = [ $entry->get_value( $attr ) ];
                $r->{$entry->dn()}->{$attr} = @{$val} > 1 ? $val : $val->[0];
            }
            $r->{$entry->dn()}->{'dn'} = $entry->dn();
        }
    }

    return( 0 ) unless $r;

    # Flatten single-key hashes
    if ( keys %{$r} == 1 ) {
        foreach my $key ( keys %{$r} ) {
            $r = $r->{$key};
        }
    }

    return( $r );
}

sub add { return( shift->{'ldap'}->add( @_ ) ); }

sub delete { return( shift->{'ldap'}->delete( @_ ) ); }

sub modify { return( shift->{'ldap'}->modify( @_ ) ); }

sub move {
    my $self = shift;

    my ( $arg );
    %{$arg} = @_;

    my ( $key, $base ) = split( /\,/, $arg->{'dn'}, 2 );

    my $obj = $self->fetch(
        base   => $base,
        filter => $key,
        attrs  => [ '*' ]
    );

    delete $obj->{'dn'};

    my $dn = $key . ',' . $arg->{'base'};

    $self->add( $dn, attr => [ %{$obj} ] );
    $self->delete( $arg->{'dn'} );

    return( 1 );
}

sub getLabels {
    my $self = shift;

    my ( $arg );
    %{$arg} = @_;

    my ( $l );

    my $desc = $self->fetch(
        base   => $arg->{'base'},
        filter => 'objectClass=organizationalUnit',
        attrs  => [ 'description' ]
    );

    foreach my $dn ( @{$arg->{'base'}} ) {
        my $label = $desc->{$dn}->{'description'} || $dn;
        $label = $1 if $label =~ /(.+?)\,$arg->{'base'}$/;
        $l->{$dn} = $label;
    }

    return( $l );
}

sub getNextNum {
    my $self = shift;

    my ( $arg );
    %{$arg} = @_;

    my $nums = $self->fetch(
        base   => $arg->{'base'},
        filter => '(' . $arg->{'unit'} . 'Number>=100)',
        attrs  => [ $arg->{'unit'} . 'Number' ]
    );

    $nums = { $nums->{$arg->{'unit'} . 'Number'} => $nums }
        if $nums->{$arg->{'unit'} . 'Number'};

    my ( @n );

    foreach (
        sort {
            $nums->{$a}->{$arg->{'unit'} . 'Number'} <=>
            $nums->{$b}->{$arg->{'unit'} . 'Number'}
        } keys %{$nums}
                                                        ) {
        push @n, $nums->{$_}->{$arg->{'unit'} . 'Number'};
    }

    @n = sort { $b <=> $a } @n;

    return( ++$n[0] );
}

1;
