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
    || die qq(Error reading configuration file pluma.cfg\n);

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
    || die qq(Error connecting to $self->{'config'}->{'ldap.Server'}\n);

    $self->{'ldap'}->bind(
        bindDN   => $self->{'config'}->{'auth.BindDN'},
        password => $self->{'config'}->{'auth.Password'}
    )
    || die qq(Error binding as $self->{'config'}->{'auth.BindDN'}\n);

    # Logging
    if ( $self->{'config'}->{'audit.log'} ) {
        if (
            $self->{'util'}->logOpen(
                log => $self->{'config'}->{'audit.log'}
            )
        ) {
            $self->{'audit'} = 1;
        }
    }

    # CGI::Application run-mode initialization
    $self->run_modes( [ qw/
        displayCreate
        displayGroup
        displayUser

        modGroup
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

sub teardown {
    my $self = shift;

    $self->{'util'}->logClose() if $self->{'audit'};
}

sub displaySearch {
    return( shift->{'util'}->wrapAll( container => 'search' ) );
}

sub displayCreate {
    my $self = shift;

    return( $self->displaySearch() ) unless (
        ( $self->{'arg'}->{'create'} ) &&
        ( $self->{'arg'}->{'create'} eq 'user' ||
          $self->{'arg'}->{'create'} eq 'group' )
    );

    return( $self->{'util'}->wrapAll(
        container => $self->{'arg'}->{'create'} . 'Add'
    ) );
}

sub displayGroup {
    my $self = shift;

    return( $self->displaySearch() ) unless $self->{'arg'}->{'group'};

    my $group = $self->{'ldap'}->fetch(
        base   => $self->{'config'}->{'ldap.Base.Group'},
        filter => 'cn=' . $self->{'arg'}->{'group'},
        attrs  => [ '*' ]
    )
    || return( $self->search( search => $self->{'arg'}->{'group'} ) );

    # Primary
    my $primary = $self->{'ldap'}->fetch(
        base   => $self->{'config'}->{'ldap.Base.User'},
        filter => 'gidNumber=' . $group->{'gidNumber'},
        attrs  => [ 'uid', 'cn' ]
    );

    if ( $primary ) {
        if ( $primary->{'uid'} ) { $primary = { p => $primary } };

        foreach ( sort keys %{$primary} ) {
            $group->{'primary'} .= $self->{'util'}->wrap(
                container => 'resultsItem',
                item      => $primary->{$_}->{'uid'},
                itemDesc  => $primary->{$_}->{'cn'} || '?',
                itemType  => 'user'
            );
        }
    }
    else {
        $group->{'primary'} = $self->{'util'}->wrap(
            container => 'error',
            error     => 'None found'
        );
    }

    # Members
    unless ( $group->{'uniqueMember'} ) {
        $group->{'members'} = $self->{'util'}->wrap(
            container => 'error',
            error     => 'None found'
        );

        return( $self->{'util'}->wrapAll(
            container => 'group', %{$group}
        ) );
    }

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

    unless ( $member ) {
        $group->{'members'} = $self->{'util'}->wrap(
            container => 'error',
            error     => 'None found'
        );

        return( $self->{'util'}->wrapAll(
            container => 'group', %{$group}
        ) );
    }

    # Single-member group support
    if ( $member->{'cn'} ) {
        my $uid = $self->{'ldap'}->fetch(
            base => $self->{'config'}->{'ldap.Base.User'},
            filter => "cn = $member->{'cn'}",
            attrs => [ 'uid' ]
        )->{'uid'};

        $member = {
            "uid=$uid," . $self->{'config'}->{'ldap.Base.User'} => $member
        };
    }

    foreach ( sort keys %{$member} ) {
        if ( /uid=(\w+)\,/ ) {
            my $user = $1;

            $group->{'members'} .= $self->{'util'}->wrap(
                container => 'resultsItem',
                item      => $user,
                itemDesc  => $member->{$_}->{'cn'} || '?',
                itemType  => 'user'
            );
        }
    }

    # Render
    return( $self->{'util'}->wrapAll( container => 'group', %{$group} ) );
}

sub displayUser {
    my $self = shift;

    return( $self->displaySearch() ) unless $self->{'arg'}->{'user'};

    my $user = $self->{'ldap'}->fetch(
        base   => $self->{'config'}->{'ldap.Base.User'},
        filter => 'uid=' . $self->{'arg'}->{'user'},
        attrs  => [ '*' ]
    )
    || return( $self->search( search => $self->{'arg'}->{'user'} ) );

    # Login shells
    unless ( $self->{'config'}->{'shells'} ) {
        push @{$self->{'config'}->{'shells'}}, '/bin/false';
    }
    $user->{'shells'} = $self->{'cgi'}->popup_menu(
        -name    => 'loginShell',
        -class   => 'dropBox',
        -values  => [ sort @{$self->{'config'}->{'shells'}} ],
        -default => $user->{'loginShell'}
    );

    # Hosts
    my ( $host );
    if ( $user->{'host'} ) {
        $user->{'host'} = [ $user->{'host'} ] unless ref $user->{'host'};
        foreach ( @{$user->{'host'}} ) { $host->{1}->{$_} = 1; }
        delete $user->{'host'};
    }

    my $hosts = $self->{'ldap'}->fetch(
        base   => $self->{'config'}->{'ldap.Base.Host'},
        filter => 'objectClass=ipHost',
        attrs  => [ 'cn' ]
    );

    if ( $hosts ) {
        $hosts = { $hosts->{'cn'} => $hosts } if $hosts->{'cn'};

        foreach ( keys %{$hosts} ) {
            $_ =~ s/cn\=(.+?)\,.*/$1/g;
            $host->{0}->{$_} = 1 unless $host->{1}->{$_};
        }
    }

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
    my $group = $self->{'ldap'}->fetch(
            base   => $self->{'config'}->{'ldap.Base.Group'},
            filter => 'objectClass=posixGroup',
            attrs  => [ 'cn', 'gidNumber', 'uniqueMember' ]
    );

    $group = { $group->{'cn'} => $group } if $group && $group->{'cn'};

    $group ||= {};

    my ( %labels );
    foreach my $g ( keys %{$group} ) {
        my $uid = $user->{'uid'};

        # Associate labels (CNs) with gidNumbers
        $labels{$group->{$g}->{'gidNumber'}} = $group->{$g}->{'cn'};

        if ( $group->{$g}->{'uniqueMember'} ) {
            $group->{$g}->{'uniqueMember'} = [ $group->{$g}->{'uniqueMember'} ]
                if not ref $group->{$g}->{'uniqueMember'}; 

            foreach ( @{$group->{$g}->{'uniqueMember'}} ) {
                $group->{1}->{$group->{$g}->{'cn'}} = 1 if /uid=$uid,/;
            }
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
    return( $self->{'util'}->wrapAll( container => 'user', %{$user} ) );
}

sub modGroup {
    my $self = shift;

    foreach my $attr ( qw/ description gidNumber / ) {
        unless ( $self->{'arg'}->{$attr} eq $self->{'arg'}->{$attr . 'Was'} ) {
            $self->{'ldap'}->modify(
                'cn=' . $self->{'arg'}->{'group'} . ','
                      . $self->{'config'}->{'ldap.Base.Group'},
                replace => { $attr => $self->{'arg'}->{$attr} }
            );

            $self->{'util'}->log(
                what => 'g:' . $self->{'arg'}->{'group'},
                item => $attr,
                object => 
                    $self->{'arg'}->{$attr}
                  . ' (was ' . $self->{'arg'}->{$attr . 'Was'} . ')',
                action => 'modify',
            ) if $self->{'audit'};
        }
    }

    return( $self->displayGroup() );
}

sub modUser {
    my $self = shift;

    # Determine whether to add/delete hosts & groups based on form submission
    foreach my $a ( qw/ userHosts_values cHosts userGroups_values cGroups / ) {
        next unless $self->{'arg'}->{$a};

        my ( $chg );

        for ( $a ) {
            /Hosts/  and do { $chg = \%{$self->{'chg'}->{'host'}}; };
            /Groups/ and do { $chg = \%{$self->{'chg'}->{'group'}}; };
        };

        foreach ( split( /,/, $self->{'arg'}->{$a} ) ) {
            next if $_ eq '*';

            if ( $a =~ /values/ ) {
                $chg->{'add'}->{$_} = 1;
            }
            else {
                my ( $o );
                if ( $a =~ /c(\w+)/ ) { $o = $1; }

                if ( $chg->{'add'}->{$_} ) {
                    delete $chg->{'add'}->{$_};
                }
                elsif ( $self->{'arg'}->{'avail' . $o} ) {
                    unless ( $self->{'arg'}->{'user' . $o . '_values'} ) {
                        $chg->{'delete'}->{$_} = 1 
                            if $self->{'arg'}->{'avail' . $o} eq $_;
                    }
                    else {
                        $chg->{'delete'}->{$_} = 1;
                    }
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

                        $self->{'util'}->log(
                            what => 'u:' . $self->{'arg'}->{'user'},
                            item => 'host',
                            object => $obj,
                            action => $action,
                        ) if $self->{'audit'};
                    };

                    /group/ and do {
                        $self->{'ldap'}->modify(
                            'cn=' . $obj . ','
                                  . $self->{'config'}->{'ldap.Base.Group'},
                            $action => { 'uniqueMember' =>
                                'uid=' . $self->{'arg'}->{'user'} . ','
                                       . $self->{'config'}->{'ldap.Base.User'} }
                        );

                        $self->{'util'}->log(
                            what => 'u:' .  $self->{'arg'}->{'user'},
                            item => 'group',
                            object => $obj,
                            action => $action,
                        ) if $self->{'audit'};
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

            $self->{'util'}->log(
                what => 'u:' . $self->{'arg'}->{'user'},
                item => $attr,
                object => 
                    $self->{'arg'}->{$attr}
                  . ' (was ' . $self->{'arg'}->{$attr . 'Was'} . ')',
                action => 'modify',
            ) if $self->{'audit'};
        }
    }

    return( $self->displayUser() );
}

sub create {
    my $self = shift;

    return( $self->displaySearch() ) unless (
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

            $create->{'attr'}->{'cn'}    = $self->{'arg'}->{'cn'};
            $create->{'attr'}->{'gecos'} = $self->{'arg'}->{'cn'};

            $create->{'attr'}->{'sn'} = $create->{'attr'}->{'cn'};
            $create->{'attr'}->{'sn'} =~ s/^.+?(\w+)$/$1/;

            $create->{'attr'}->{'givenName'} = $create->{'attr'}->{'cn'};
            $create->{'attr'}->{'givenName'} =~ s/^(\w+).+?$/$1/;

            $create->{'attr'}->{'uid'} = $self->{'arg'}->{'uid'};

            if ( $self->{'config'}->{'mail.Format'} ) {
                $create->{'attr'}->{'mail'} = $self->{'config'}->{'mail.Format'};

                foreach ( qw/ sn givenName uid / ) {
                    $create->{'attr'}->{'mail'}
                        =~ s/\%$_/$create->{'attr'}->{$_}/g;
                }
            }

            $self->{'config'}->{'prefix.Home'} ||= '/home/';
            $self->{'config'}->{'prefix.Home'} .= '/' unless /\/$/;
            $create->{'attr'}->{'homeDirectory'} =
                $self->{'config'}->{'prefix.Home'} . $self->{'arg'}->{'uid'};

            $create->{'attr'}->{'uidNumber'} = $self->{'ldap'}->getNextNum(
                base => $self->{'config'}->{'ldap.Base.User'},
                unit => 'uid'
            );

            $self->{'config'}->{'default.GID'} ||= '100';
            $create->{'attr'}->{'gidNumber'}
                = $self->{'config'}->{'default.GID'};

            $create->{'attr'}->{'objectClass'} = [ qw/
                top
                person
                organizationalPerson
                inetOrgPerson
                posixAccount
                account
            / ];

            if ( $self->{'config'}->{'user.objectClass'} ) {
                push @{$create->{'attr'}->{'objectClass'}},
                    @{$self->{'config'}->{'user.objectClass'}};
            }

            $self->{'util'}->log(
                what => 'u:' .  $self->{'arg'}->{'user'},
                action => 'create'
            ) if $self->{'audit'};
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

            $self->{'util'}->log(
                what => 'g:' .  $self->{'arg'}->{'group'},
                action => 'create'
            ) if $self->{'audit'};
        };
    }

    $self->{'ldap'}->add( $create->{'dn'}, attr => [ %{$create->{'attr'}} ] );

    for ( $self->{'arg'}->{'create'} ) {
        /user/  && return( $self->displayUser() );
        /group/ && return( $self->displayGroup() );
    }
}

sub delete {
    my $self = shift;

    if ( $self->{'arg'}->{'user'} ) {
        $self->{'ldap'}->delete(
            'uid=' . $self->{'arg'}->{'user'} . ','
                   . $self->{'config'}->{'ldap.Base.User'}
        );
    
        my $filter = 'uniqueMember=uid=' . $self->{'arg'}->{'user'}
            . ',' . $self->{'config'}->{'ldap.Base.User'};

        my $group = $self->{'ldap'}->fetch(
            base   => $self->{'config'}->{'ldap.Base.Group'},
            filter => $filter,
            attrs  => [ 'cn' ]
        );

        if ( $group ) {
            $group = { 'g' => $group } if $group->{'cn'};

            foreach my $g ( keys %{$group} ) {
                $self->{'ldap'}->modify(
                    'cn=' . $group->{$g}->{'cn'} . ','
                          . $self->{'config'}->{'ldap.Base.Group'},
                    delete => { 'uniqueMember' =>
                        'uid=' . $self->{'arg'}->{'user'} . ','
                               . $self->{'config'}->{'ldap.Base.User'} }
                );
            }
        }

        $self->{'utli'}->log(
            what => 'u:' .  $self->{'arg'}->{'user'},
            action => 'delete'
        ) if $self->{'audit'};

        delete $self->{'arg'}->{'user'};
    }

    if ( $self->{'arg'}->{'group'} ) {
        $self->{'ldap'}->delete(
            'cn=' . $self->{'arg'}->{'group'} . ','
                  . $self->{'config'}->{'ldap.Base.Group'}
        );

        $self->{'util'}->log(
            what => 'g:' .  $self->{'arg'}->{'group'},
            action => 'delete'
        ) if $self->{'audit'};

        delete $self->{'arg'}->{'group'};
    }

    return( $self->displaySearch() );
}

sub password {
    my $self = shift;

    return( $self->displayUser() ) unless $self->{'arg'}->{'password'};

    my $pwCrypt = $self->{'util'}->pwEncrypt(
        text   => $self->{'arg'}->{'password'},
        digest => $self->{'config'}->{'pw.Encrypt'}
    )
    || die qq(Error attempting to encrypt password\n);

    $self->{'ldap'}->modify(
        'uid=' . $self->{'arg'}->{'user'} . ','
               . $self->{'config'}->{'ldap.Base.User'},
        replace => { userPassword => $pwCrypt }
    );

    $self->{'util'}->log(
        what => 'u:' .  $self->{'arg'}->{'user'},
        action => 'password modify'
    ) if $self->{'audit'};

    return( $self->displayUser() );
}

sub search {
    my $self = shift;

    return( $self->displaySearch() ) unless $self->{'arg'}->{'search'};

    unless ( $self->{'arg'}->{'search'} ) {
        my ( $arg );
        %{$arg} = @_;

        $self->{'arg'}->{'search'} ||= $arg->{'search'};
    }

    $self->{'arg'}->{'search'} = '' if $self->{'arg'}->{'search'} eq '*';

    my $user = $self->{'ldap'}->fetch(
        base   => $self->{'config'}->{'ldap.Base.User'},
        filter =>
            '(| (uid=' . $self->{'arg'}->{'search'} . '*)'
             . '(givenName=' . $self->{'arg'}->{'search'} . '*)'
             . '(sn=' . $self->{'arg'}->{'search'} . '*) )',
        attrs  => [ '*' ]
    ) || {};
    my $group = $self->{'ldap'}->fetch(
        base   => $self->{'config'}->{'ldap.Base.Group'},
        filter => 'cn=' . $self->{'arg'}->{'search'} . '*',
        attrs  => [ '*' ]
    ) || {};

    $user  = { 'u' => $user }  if $user->{'uid'};
    $group = { 'g' => $group } if $group->{'cn'};

    my $search = { %{$user}, %{$group} };

    unless ( keys %{$search} ) {
        return( $self->{'util'}->wrapAll(
            container => 'results',
            results   => $self->{'util'}->wrap(
                container => 'error',
                error     => 'No matches found'
            )
        ) );
    }

    # Return a list
    return( $self->{'util'}->wrapAll(
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

                $results .= $self->{'util'}->wrap(
                    container => 'resultsItem',
                    item      => $search->{$_}->{'uid'} || $search->{$_}->{'cn'},
                    itemDesc  => $search->{$_}->{'description'}
                              || $search->{$_}->{'cn'} || '?',
                    itemType  => $type
                )
            }

            return( $results );
        }
    ) );
}

1;
