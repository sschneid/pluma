# pluma.pm
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
# $Id: pluma.pm,v 1.8 2008/08/11 20:20:03 schneis Exp $

package pluma;

use base 'CGI::Application';

use pluma::LDAP;
use pluma::Util;

use strict;
use warnings;

sub setup {
    my $self = shift;

    $self->{'util'} = pluma::Util->new();

    # Read configuration from pluma.cfg
    $self->{'config'} = $self->{'util'}->readConfig( configFile => 'pluma.cfg' )
    || do {
        print qq(Error reading configuration file pluma.cfg\n);
        exit( 1 );
    };

    # Read and untaint CGI parameters
    $self->{'cgi'} = $self->query();

    map {
        my $raw = [ $self->{'cgi'}->param($_) ];
        $self->{'arg'}->{$_} = @$raw > 1 ? $raw : $raw->[0];
    } $self->{'cgi'}->param();

    $self->{'arg'} = $self->{'util'}->untaintCGI( cgi => $self->{'cgi'} );

    # Connect and bind to LDAP server
    $self->{'ldap'} = pluma::LDAP->new(
        server => $self->{'config'}->{'ldap.Server'},
        SSL    => $self->{'config'}->{'ldap.SSL'}
    )
    || do {
        print qq(Error connecting to $self->{'config'}->{'ldap.Server'}\n);
        exit( 1 );
    };

    $self->{'ldap'}->bind(
        bindDN   => $self->{'config'}->{'auth.BindDN'},
        password => $self->{'config'}->{'auth.Password'}
    )
    || do {
        print qq(Error binding as $self->{'config'}->{'auth.BindDN'}\n);
        exit( 1 );
    };

    # CGI::Application run-mode initialization
    $self->run_modes( [ qw/
        displayCreate
        displayGroup
        displayUser

        modUser

        create
        delete
        password
        search
    / ] );

    $self->{'arg'}->{'user'}
        ? $self->start_mode( 'displayUser' )
        : $self->start_mode( 'displayGroup' );

    return( $self );
}

sub displaySearch {
    return( shift->_wrapAll( container => 'search' ) );
}

sub displayCreate {
    my $self = shift;

    return $self->displaySearch() unless (
        ( $self->{'arg'}->{'create'} ) &&
        ( $self->{'arg'}->{'create'} eq 'user' ||
          $self->{'arg'}->{'create'} eq 'group' )
    );

    return( $self->_wrapAll( container => $self->{'arg'}->{'create'} . 'Add' ) );
}

sub displayGroup {
    my $self = shift;

    return $self->displaySearch() unless $self->{'arg'}->{'group'};

    my $group = $self->{'ldap'}->fetch(
        base   => $self->{'config'}->{'ldap.Base.Group'},
        filter => 'cn=' . $self->{'arg'}->{'group'},
        attrs  => [ '*' ]
    )
    || return( 'nomatch' );

    # Is there a description?
    $group->{'description'} ||= '?';

    # Members
    $group->{'uniqueMember'} = [ $group->{'uniqueMember'} ]
        unless ref $group->{'uniqueMember'};

    my $filter = '(| ';
    foreach ( @{$group->{'uniqueMember'}} ) { $filter .= "($1)" if /^(.+?)\,/; }
    $filter .= ' )';

    my $member = $self->{'ldap'}->fetch(
        base   => $self->{'config'}->{'ldap.Base.User'},
        filter => $filter,
        attrs  => [ 'cn' ]
    );

    # No need to continue if the group doesn't have any members
    return $self->_wrapAll( container => 'group', %{$group} ) unless $member;

    # Single-member group support
    if ( $member->{'cn'} ) {
        my $uid = $self->{'ldap'}->fetch(
            base => $self->{'config'}->{'ldap.Base.User'},
            filter => "cn = $member->{'cn'}",
            attrs => [ 'uid' ]
        )->{'uid'};

        $member = { "uid=$uid," . $self->{'config'}->{'ldap.Base.User'} => $member };
    }

    foreach ( sort keys %{$member} ) {
        if ( /uid=(\w+)\,/ ) {
            my $user = $1;

            $group->{'members'} .= $self->_wrap(
                container => 'resultsItem',
                item      => $user,
                itemDesc  => $member->{$_}->{'cn'} || '?',
                itemType  => 'user'
            );
        }
    }

    # Render
    return $self->_wrapAll( container => 'group', %{$group} );
}

sub displayUser {
    my $self = shift;

    return $self->displaySearch() unless $self->{'arg'}->{'user'};

    my $user = $self->{'ldap'}->fetch(
        base   => $self->{'config'}->{'ldap.Base.User'},
        filter => 'uid=' . $self->{'arg'}->{'user'},
        attrs  => [ '*' ]
    )
    || return $self->search( search => $self->{'arg'}->{'user'} );

    # Login shells
    $user->{'shells'} = $self->{'cgi'}->popup_menu(
        -name    => 'loginShell',
        -class   => 'dropBox',
        -values  => [ sort @{$self->{'config'}->{'shells'}} ],
        -default => $user->{'loginShell'}
    );

    # Hosts
    my ( $host );
    $user->{'host'} = [ $user->{'host'} ] unless ref $user->{'host'};
    foreach ( @{$user->{'host'}} ) { $host->{1}->{$_} = 1; }
    foreach (
        keys %{$self->{'ldap'}->fetch(
            base   => $self->{'config'}->{'ldap.Base.Host'},
            filter => 'objectClass=ipHost',
            attrs  => [ 'cn' ]
        )}
    ) {
        $_ =~ s/cn\=(.+?)\,.*/$1/g;
        $host->{0}->{$_} = 1 unless $host->{1}->{$_};
    }
    delete $user->{'host'};
    $user->{'availHosts'} = $self->{'cgi'}->scrolling_list(
        -name => 'availHosts', -values => [ sort keys %{$host->{0}} ],
        -size => 7,            -class  => 'selectBox'
    );
    $user->{'userHosts'}  = $self->{'cgi'}->scrolling_list(
        -name => 'userHosts',  -values => [ sort keys %{$host->{1}} ],
        -size => 7,            -class  => 'selectBox'
    );

    $user->{'cHosts'} = join( ',', sort keys %{$host->{1}} );

    # Groups
    my ( $group );
    %{$group} = %{$self->{'ldap'}->fetch(
            base   => $self->{'config'}->{'ldap.Base.Group'},
            filter => 'objectClass=posixGroup',
            attrs  => [ 'cn', 'gidNumber', 'uniqueMember' ]
    )};

    my ( %labels );
    foreach my $g ( keys %{$group} ) {
        my $uid = $user->{'uid'};

        # Associate labels (CNs) with gidNumbers
        $labels{$group->{$g}->{'gidNumber'}} = $group->{$g}->{'cn'};

        # Push single-user uniqueMember into an array
        $group->{$g}->{'uniqueMember'} = [ $group->{$g}->{'uniqueMember'} ]
            if not ref $group->{$g}->{'uniqueMember'}; 

        foreach ( @{$group->{$g}->{'uniqueMember'}} ) {
            next unless $group->{1}->{$group->{$g}->{'cn'}};
            $group->{1}->{$group->{$g}->{'cn'}} = 1 if /uid=$uid,/;
        }

        $group->{0}->{$group->{$g}->{'cn'}} = 1
            unless $group->{1}->{$group->{$g}->{'cn'}};
    }

    # Default gidNumber
    $user->{'groups'} = $self->{'cgi'}->popup_menu(
        -name    =>  'gidNumber',
        -class   => 'dropBox',
        -values  => [ sort { $labels{$a} cmp $labels{$b} } keys %labels ],
        -default => $user->{'gidNumber'},
        -labels  => \%labels,
    );

    # Available/member-of group
    $user->{'availGroups'} = $self->{'cgi'}->scrolling_list(
        -name => 'availGroups', -values => [ sort keys %{$group->{0}} ],
        -size => 7,             -class  => 'selectBox'
    );
    $user->{'userGroups'}  = $self->{'cgi'}->scrolling_list(
        -name => 'userGroups',  -values => [ sort keys %{$group->{1}} ],
        -size => 7,             -class  => 'selectBox'
    );

    $user->{'cGroups'} = join( ',', sort keys %{$group->{1}} );

    # Render
    return $self->_wrapAll( container => 'user', %{$user} );
}

sub modUser {
    my $self = shift;

    # Determine whether to add/delete hosts & groups based on form submission
    foreach my $a ( qw/ userHosts_values cHosts userGroups_values cGroups / ) {
        next unless $self->{'arg'}->{$a};

        my ( $chg );

        for ( $a ) {
            /cHosts/  and do { next unless $self->{'arg'}->{'userHosts_values'}; };
            /cGroups/ and do { next unless $self->{'arg'}->{'userGroups_values'}; };

            /Hosts/  and do { $chg = \%{$self->{'chg'}->{'host'}}; };
            /Groups/ and do { $chg = \%{$self->{'chg'}->{'group'}}; };
        };

        foreach ( split( /,/, $self->{'arg'}->{$a} ) ) {
            next if $_ eq '*';

            if ( $a =~ /values/ ) {
                $chg->{'add'}->{$_} = 1;
            }
            else {
                if ( $chg->{'add'}->{$_} ) {
                    delete $chg->{'add'}->{$_};
                }
                else {
                    $chg->{'delete'}->{$_} = 1;
                }
            }
        }
    }

    # Publish the changes to LDAP
    foreach my $a ( keys %{$self->{'chg'}} ) {
        foreach my $action ( keys %{$self->{'chg'}->{$a}} ) {
            foreach my $obj ( keys%{$self->{'chg'}->{$a}->{$action}} ) {
                for ( $a ) {
                    /host/ and do {
                        $self->{'ldap'}->modify(
                            'uid=' . $self->{'arg'}->{'user'} . ','
                                   . $self->{'config'}->{'ldap.Base.User'},
                            $action => { 'host' => $obj }
                        );
                    };

                    /group/ and do {
                        $self->{'ldap'}->modify(
                            'cn=' . $obj . ','
                                  . $self->{'config'}->{'ldap.Base.Group'},
                            $action => { 'uniqueMember' =>
                                'uid=' . $self->{'arg'}->{'user'} . ','
                                       . $self->{'config'}->{'ldap.Base.User'} }
                        );
                    };
                };
            }
        }
    }

    foreach my $attr ( qw/ cn gidNumber homeDirectory loginShell mail uidNumber / ) {
        unless ( $self->{'arg'}->{$attr} eq $self->{'arg'}->{$attr . 'Was'} ) {
            $self->{'ldap'}->modify(
                'uid=' . $self->{'arg'}->{'user'} . ','
                       . $self->{'config'}->{'ldap.Base.User'},
                replace => { $attr => $self->{'arg'}->{$attr} }
            );
        }
    }

    return $self->displayUser();
}

sub create {
    my $self = shift;

    return $self->displaySearch() unless (
        ( $self->{'arg'}->{'create'} ) &&
        ( $self->{'arg'}->{'create'} eq 'user' ||
          $self->{'arg'}->{'create'} eq 'group' )
    );

    my ( $create );

    for ( $self->{'arg'}->{'create'} ) {
        /user/ && do {
            $self->{'arg'}->{'user'} = $self->{'arg'}->{'uid'};

            $create->{'dn'} = 'uid=' . $self->{'arg'}->{'uid'} . ','
                . $self->{'config'}->{'ldap.Base.User'};

            $create->{'attr'}->{'cn'}= $self->{'arg'}->{'cn'};

            $create->{'attr'}->{'sn'} = $create->{'attr'}->{'cn'};
            $create->{'attr'}->{'sn'} =~ s/^.+?(\w+)$/$1/;

            $create->{'attr'}->{'homeDirectory'} = '/home/'
                . $self->{'arg'}->{'uid'};

            $create->{'attr'}->{'uidNumber'} = $self->_getNextNum(
                base => $self->{'config'}->{'ldap.Base.User'},
                unit => 'uid'
            );

            $create->{'attr'}->{'gidNumber'}   = $self->{'config'}->{'default.GID'};
            $create->{'attr'}->{'objectClass'} = [ qw/
                top
                person
                organizationalPerson
                inetOrgPerson
                posixAccount
                account
            / ];
        };

        /group/ && do {
            $self->{'arg'}->{'group'} = $self->{'arg'}->{'cn'};

            $create->{'dn'} = 'cn=' . $self->{'arg'}->{'cn'} . ','
                . $self->{'config'}->{'ldap.Base.Group'};

            $create->{'attr'}->{'cn'}          = $self->{'arg'}->{'cn'};
            $create->{'attr'}->{'description'} = $self->{'arg'}->{'description'};

            $create->{'attr'}->{'gidNumber'} = $self->_getNextNum(
                base => $self->{'config'}->{'ldap.Base.Group'},
                unit => 'gid'
            );

            $create->{'attr'}->{'objectClass'} = [ qw/
                top
                posixGroup
                groupOfNames
                groupOfUniqueNames
            / ];
        };
    }

    $self->{'ldap'}->add( $create->{'dn'}, attr => [ %{$create->{'attr'}} ] );

    for ( $self->{'arg'}->{'create'} ) {
        /user/  && return $self->displayUser();
        /group/ && return $self->displayGroup();
    }
}

sub delete {
    my $self = shift;

    if ( $self->{'arg'}->{'user'} ) {
        $self->{'ldap'}->delete(
            'uid=' . $self->{'arg'}->{'user'} . ','
                   . $self->{'config'}->{'ldap.Base.User'}
        );

        delete $self->{'arg'}->{'user'};
    }

    if ( $self->{'arg'}->{'group'} ) {
        $self->{'ldap'}->delete(
            'cn=' . $self->{'arg'}->{'group'} . ','
                  . $self->{'config'}->{'ldap.Base.Group'}
        );

        delete $self->{'arg'}->{'group'};
    }

    return $self->displaySearch();
}

sub password {
    my $self = shift;

    my $pwSalt = join '',
        ('.', '/', 0..9, 'A'..'Z', 'a'..'z')[rand 64, rand 64];

    my $pwCrypt = crypt($self->{'arg'}->{'password'}, $pwSalt);

    $self->{'ldap'}->modify(
        'uid=' . $self->{'arg'}->{'user'} . ','
               . $self->{'config'}->{'ldap.Base.User'},
        replace => {
            userPassword => '{crypt}' . $pwCrypt
        }
    );

    return $self->displayUser();
}

sub search {
    my $self = shift;

    return $self->displaySearch() unless $self->{'arg'}->{'search'};

    unless ( $self->{'arg'}->{'search'} ) {
        my ( $arg );
        %{$arg} = @_;

        $self->{'arg'}->{'search'} ||= $arg->{'search'};
    }

    my $user = $self->{'ldap'}->fetch(
        base   => $self->{'config'}->{'ldap.Base.User'},
        filter =>
            '(| (uid=' . $self->{'arg'}->{'search'} . '*)'
             . '(cn='  . $self->{'arg'}->{'search'} . '*) )',
        attrs  => [ '*' ]
    ) || {};
    my $group = $self->{'ldap'}->fetch(
        base   => $self->{'config'}->{'ldap.Base.Group'},
        filter => 'cn=' . $self->{'arg'}->{'search'} . '*',
        attrs  => [ '*' ]
    ) || {};

    $user  = { '1' => $user }  if $user->{'uid'};
    $group = { '1' => $group } if $group->{'cn'};

    my $search = { %{$user}, %{$group} };

    return( 'nomatch' ) unless $search;

    # Return a list
    return $self->_wrapAll(
        container => 'results',
        results    => sub {
            my ( $results );

            foreach ( sort keys %{$search} ) {
                my ( $type );

                if (
                    $search->{$_}->{'uidNumber'} || $search->{$_}->{'gidNumber'}
                ) {
                    $type = $search->{$_}->{'uidNumber'} ? 'user' : 'group';
                }
                else {
                    next;
                }

                $results .= $self->_wrap(
                    container => 'resultsItem',
                    item      => $search->{$_}->{'uid'} || $search->{$_}->{'cn'},
                    itemDesc  => $search->{$_}->{'cn'} || '?',
                    itemType  => $type
                )
            }

            return $results;
        }
    );
}

sub _getNextNum {
    my $self = shift;

    my ( $arg );
    %{$arg} = @_;

    my $nums = $self->{'ldap'}->fetch(
        base   => $arg->{'base'},
        filter => '(' . $arg->{'unit'} . 'Number>=100)',
        attrs  => [ $arg->{'unit'} . 'Number' ]
    );

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

    return ++$n[0];
}

sub _wrap {
    my $self = shift;

    my ( $arg );
    %{$arg} = @_;

    my $template = $self->load_tmpl(
        $arg->{'container'} . '.thtml',
        die_on_bad_params => 0,
        cache => 1
    );

    delete $arg->{'container'};

    map {
        chomp( $arg->{$_} );
        $template->param( $_ => $arg->{$_} );
    } keys %{$arg};

    return( $template->output() );
}

sub _wrapAll {
    my $self = shift;

    my ( $arg );
    %{$arg} = @_;

    my $template = $self->load_tmpl(
        $arg->{'container'} . '.thtml',
        die_on_bad_params => 0,
        cache => 1
    );

    delete $arg->{'container'};

    map {
        chomp( $arg->{$_} );
        $template->param( $_ => $arg->{$_} );
    } keys %{$arg};

    my $page = $self->load_tmpl(
        'index.thtml',
        die_on_bad_params => 0,
        cache => 1
    );

    $page->param( container => $template->output() );

    return( $page->output() );
}

1;
