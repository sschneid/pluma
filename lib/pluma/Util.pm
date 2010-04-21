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

package pluma::Util;

@ISA = qw( pluma );

use POSIX qw( strftime );

use strict;
use warnings;

sub new { return( bless {}, shift ); }

sub log {
    my $self = shift;
        
    my ( $arg );
    %{$arg} = @_;

    my $stamp = '[' . strftime( "%e/%b/%Y:%H:%M:%S", localtime() ) . ']';
                   
    if ( $arg->{'item'} && $arg->{'object'} ) {
        print LOG join( ' ',
            $ENV{'REMOTE_USER'}, $stamp,
            $arg->{'what'} . ':',
            $arg->{'item'}, $arg->{'action'}, $arg->{'object'}
        ) . "\n";
    }
    else {
        print LOG join( ' ',
            $ENV{'REMOTE_USER'}, $stamp, $arg->{'what'} . ': ' . $arg->{'action'}
        ) . "\n";
    }
                            
    return( 1 );
}

sub logClose {
    my $self = shift;

    close( LOG );

    return( 1 );
}

sub logOpen {
    my $self = shift;

    my ( $arg );
    %{$arg} = @_;

    ( $arg->{'log'} ) || return( 0 );

    open( LOG, "+>>$arg->{'log'}" ) || return( 0 );

    return( 1 );
}

sub pwEncrypt {
    my $self = shift;

    my ( $arg );
    %{$arg} = @_;

    ( $arg->{'text'} && $arg->{'digest'} ) || return( 0 );

    my $salt = join '',
        ('.', '/', 0..9, 'A'..'Z', 'a'..'z')[rand 64, rand 64];

    my ( $pwCrypt );

    for ( $arg->{'digest'} ) {
        ( /^sha$/ || /^ssha$/ ) && do {
            return( 0 ) unless ( eval "require Digest::SHA1" );
            return( 0 ) unless ( eval "require MIME::Base64" );

            my $sha1 = Digest::SHA1->new();
            $sha1->add( $arg->{'text'} );

            /^sha$/ && do {
                $pwCrypt = '{sha}'  . MIME::Base64::encode_base64(
                    $sha1->digest(), ''
                );
            };

            /^ssha$/ && do {
                $sha1->add( $salt );
                $pwCrypt = '{ssha}' . MIME::Base64::encode_base64(
                    $sha1->digest() . $salt, ''
                );
            };

            last;
        };

        # Default to crypt
        $pwCrypt = '{crypt}' . crypt( $arg->{'text'}, $salt );
    }

    return( $pwCrypt );
}

sub readConfig {
    my $self = shift;

    my ( $arg );
    %{$arg} = @_;

    my ( $config );

    $arg->{'configFile'} || return( 0 );

    if ( -e $arg->{'configFile'} ) {
        open( CONFILE, $arg->{'configFile'} ) || return( 0 );

        while( <CONFILE> ) {
            $config->{lc( $1 )} = $2 if /^\$(.+?):.+?"(.+?)"/;
            ( @{$config->{lc( $1 )}} ) = split( / /, $2 ) if /^\@(.+?):.+?"(.+?)"/;
        }
        close( CONFILE );
    }
    else {
        return( 0 );
    }

    map {
        if ( ref $config->{$_} ) {
            foreach ( @{$config->{$_}} ) {
                $_ =~ s/\$([\w.]+)/$config->{lc( $1 )}/g;
                $_ =~ s/\\s/ /g;
            }
        }
        else {
            $config->{$_} =~ s/\$([\w.]+)/$config->{lc( $1 )}/g;
            $config->{$_} =~ s/\\s/ /g;
        }
    } keys %{$config};

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

sub wrap {
    my $self = shift;

    my ( $arg );
    %{$arg} = @_;

    my $template = $self->load_tmpl(
        'thtml/' . $arg->{'container'} . '.thtml',
        die_on_bad_params => 0,
        cache => 1
    );

    delete $arg->{'container'};

    map {
        if ( $arg->{$_} ) {
            chomp( $arg->{$_} );
            $template->param( $_ => $arg->{$_} );
        }
    } keys %{$arg};

    return( $template->output() );
}

sub wrapAll {
    my $self = shift;

    my ( $arg );
    %{$arg} = @_;

    my $template = $self->load_tmpl(
        'thtml/' . $arg->{'container'} . '.thtml',
        die_on_bad_params => 0,
        cache => 1
    );

    delete $arg->{'container'};

    map {
        chomp( $arg->{$_} ) if $arg->{$_};
        $template->param( $_ => $arg->{$_} );
    } keys %{$arg};

    my $page = $self->load_tmpl(
        'thtml/' . 'index.thtml',
        die_on_bad_params => 0,
        cache => 1
    );

    $page->param( container => $template->output() );

    return( $page->output() );
}

1;
