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

    # Load pluma::Util and read system configuration from pluma.cfg
    $self->{'util'} = pluma::Util->new();

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
        server => $self->{'config'}->{'ldap.server'},
        SSL    => $self->{'config'}->{'ldap.ssl'}
    )
    || die qq(Error connecting to $self->{'config'}->{'ldap.server'}\n);

    $self->{'ldap'}->bind(
        bindDN   => $self->{'config'}->{'auth.binddn'},
        password => $self->{'config'}->{'auth.password'}
    )
    || die qq(Error binding as $self->{'config'}->{'auth.binddn'}\n);

    # Find user base DN(s) if not specified
    unless ( $self->{'config'}->{'ldap.base.user'} ) {
        my ( $dn );

        foreach (
            keys %{$self->{'ldap'}->fetch(
                base   => $self->{'config'}->{'ldap.base'},
                filter => 'objectClass=person',
                attrs  => [ 'dn' ]
            )}
        ) {
            $dn->{$1} = 1 if /^uid=.+?,\s*(.*)$/
        }

        if ( keys %{$dn} > 1 ) {
            $self->{'config'}->{'ldap.base.user'} = [ keys %{$dn} ];
        }
        else {
            map { $self->{'config'}->{'ldap.base.user'} = $_; } keys %{$dn};
        }
    }

    $self->{'ldap'}->set( %{$self->{'config'}} );

    # User defaults if not specified
    $self->{'config'}->{'user.uniqueID'}     ||= 'uid';
    $self->{'config'}->{'group.objectClass'} ||= 'groupOfUniqueNames';
    $self->{'config'}->{'group.memberAttribute'} ||= 'uniqueMember';
    $self->{'config'}->{'mail.WelcomeLetter.template'} ||= 'email';

    unless( defined( $self->{'config'}->{'user.posix.hosts'} ) ) {
        $self->{'config'}->{'user.posix.hosts'} = '1';
    }

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
        disable
        enable
        password
        rename
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
    $self->{'ldap'}->disconnect();
}

sub displaySearch {
    my $self = shift;

    my ( $arg );
    %{$arg} = @_;

    my $error = $self->{'util'}->wrap(
        container => 'error',
        error     => $arg->{'error'}
    ) if $arg->{'error'};

    if ( ref $self->{'config'}->{'ldap.base.user'} ) {
        my $labels = $self->{'ldap'}->getLabels(
            base => $self->{'config'}->{'ldap.base.user'}
        );

        $labels->{''} = ' All ';

        return( $self->{'util'}->wrapAll(
            container => 'search',
            base => $self->{'cgi'}->popup_menu(
                -name    => 'base',
                -class   => 'dropBox',
                -values  => [ sort {
                                $labels->{$a} cmp $labels->{$b}
                            } keys %{$labels} ],
                -labels  => $labels
            ),
            error     => $error
        ) );
    }
    else {
        return( $self->{'util'}->wrapAll(
            container => 'search',
            error => $error
        ) );
    }
}

sub displayCreate {
    my $self = shift;

    return( $self->displaySearch() ) unless (
        ( $self->{'arg'}->{'create'} ) &&
        ( $self->{'arg'}->{'create'} eq 'user' ||
          $self->{'arg'}->{'create'} eq 'group' )
    );

    my ( $arg );
    %{$arg} = @_;

    my $error = $self->{'util'}->wrap(
        container => 'error',
        error     => $arg->{'error'}
    ) if $arg->{'error'};

    if (
        ( $self->{'arg'}->{'create'} eq 'user' ) &&
        ( ref $self->{'config'}->{'ldap.base.user'} )
    ) {
        my $labels = $self->{'ldap'}->getLabels(
            base => $self->{'config'}->{'ldap.base.user'}
        );

        return( $self->{'util'}->wrapAll(
            container  => $self->{'arg'}->{'create'} . 'Add',
            base       => $self->{'util'}->wrap(
                container => 'selectBase',
                bases     => $self->{'cgi'}->popup_menu(
                    -name    => 'base',
                    -class   => 'dropBox',
                    -values  => [ sort {
                                    $labels->{$a} cmp $labels->{$b}
                                } keys %{$labels} ],
                    -labels  => $labels,
                )
            ),
            mailformat => $self->{'config'}->{'mail.format'},
            letter     => sub {
                if ( $self->{'config'}->{'mail.welcomeletter'} ) {
                    return( $self->{'util'}->wrap(
                        container => 'selectWelcomeLetter'
                    ) );
                }
                else {
                    return( '' );
                }
            },
            error      => $error
        ) );
    }
    else {
        return( $self->{'util'}->wrapAll(
            container  => $self->{'arg'}->{'create'} . 'Add',
            letter     => sub {
                if ( $self->{'config'}->{'mail.welcomeletter'} ) {
                    return( $self->{'util'}->wrap(
                        container => 'selectWelcomeLetter'
                    ) );
                }
                else {
                    return( '' );
                }
            },
            mailformat => $self->{'config'}->{'mail.format'},
            error      => $error
        ) );
    }
}

sub displayGroup {
    my $self = shift;

    return( $self->displaySearch() ) unless $self->{'arg'}->{'group'};

    my $group = $self->{'ldap'}->fetch(
        base   => $self->{'config'}->{'ldap.base.group'},
        filter =>
            '(& (objectClass=' . $self->{'config'}->{'group.objectclass'} . ')'
             . '(cn=' . $self->{'arg'}->{'group'} . ') )',
        attrs  => [ '*' ]
    )
    || return( $self->search( search => $self->{'arg'}->{'group'} ) );

    for ( @{$group->{'objectClass'}} ) { $group->{'_objectClass'}->{lc( $_ )} = 1; }
    $self->{'config'}->{'group.posix'} = 0
        unless $group->{'_objectClass'}->{'posixgroup'};

    # Primary
    if (
        $self->{'config'}->{'user.posix'} &&
        $self->{'config'}->{'group.posix'}
    ) {
        my $primary = $self->{'ldap'}->fetch(
            base   => $self->{'config'}->{'ldap.base.user'},
            filter => 'gidNumber=' . $group->{'gidNumber'},
            attrs  => [ 'uid', 'cn' ]
        );

        if ( $primary ) {
            if ( $primary->{'uid'} ) { $primary = { p => $primary } };

            $group->{'primary'} = '<table>';

            my $c = 0;
            foreach my $i ( sort keys %{$primary} ) {
                $group->{'primary'} .= $self->{'util'}->wrap(
                    container => 'resultsItem',
                    eo        => sub {
                        if ( $c % 2 ) { return( 'odd' ); } else { return( 'even' ); }
                    },
                    item      => $primary->{$i}->{'uid'},
                    itemType  => 'user',
                    itemDesc  => $primary->{$i}->{'cn'} || '?',
                );

                $c++;
            }

            $group->{'primary'} .= '</table>';
        }
        else {
            $group->{'primary'} = $self->{'util'}->wrap(
                container => 'error',
                error     => 'None found'
            );
        }
    }
    else {
        $group->{'primary'} = $self->{'util'}->wrap(
            container => 'error',
            error     => 'POSIX user support is disabled'
        );
    }

    # Members
    unless ( $group->{$self->{'config'}->{'group.memberAttribute'}} ) {
        $group->{'members'} = $self->{'util'}->wrap(
            container => 'error',
            error     => 'None found'
        );

        return( $self->{'util'}->wrapAll(
            container => 'group', %{$group}
        ) );
    }

    $group->{$self->{'config'}->{'group.memberAttribute'}} = [ $group->{$self->{'config'}->{'group.memberAttribute'}} ]
        unless ref $group->{$self->{'config'}->{'group.memberAttribute'}};

    my $filter = '(| ';
    foreach ( @{$group->{$self->{'config'}->{'group.memberAttribute'}}} ) { $filter .= "($1)" if /^(.+?)\,/; }
    $filter .= ' )';

    my $member = $self->{'ldap'}->fetch(
        base   => $self->{'config'}->{'ldap.base.user'},
        filter => $filter,
        attrs  => [ 'cn', 'mail', 'nsAccountLock' ]
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
            base   => $self->{'config'}->{'ldap.base.user'},
            filter => "cn = $member->{'cn'}",
            attrs  => [ 'uid' ]
        )->{'uid'};

        $member = {
            "uid=$uid," . $self->{'config'}->{'ldap.base.user'} => $member
        };
    }

    $group->{'members'} = '<table>';

    if ( $self->{'config'}->{'group.posix'} ) { 
        $group->{'cntr'} = 'resultsItem';
    }

    my $c = 0;
    foreach my $i ( sort keys %{$member} ) {
        if ( $i =~ /uid=(\w+)\,/ ) {
            my $user = $1;

            $group->{'members'} .= $self->{'util'}->wrap(
                container => $group->{'cntr'} || 'resultsItemExt',
                eo        => sub {
                    if ( $c % 2 ) { return( 'odd' ); } else { return( 'even' ); }
                },
                item      => $user,
                itemType  => 'user',
                itemDesc  => $member->{$i}->{'cn'} || '?',
                itemDesc2 => $member->{$i}->{'mail'},
                itemDesc3 => sub {
                    return( 'Disabled') if $member->{$i}->{'nsAccountLock'};
                }
            );

            $c++;
        }
    }

    $group->{'members'} .= '</table>';

    # Render
    if ( $self->{'config'}->{'group.posix'} ) {
        return( $self->{'util'}->wrapAll( container => 'group', %{$group} ) );
    }
    else {
        return( $self->{'util'}->wrapAll( container => 'groupNonPOSIX', %{$group} ) );
    }
}

sub displayUser {
    my $self = shift;

    return( $self->displaySearch() ) unless $self->{'arg'}->{'user'};

    my $user = $self->{'ldap'}->fetch(
        base   => $self->{'config'}->{'ldap.base.user'},
        filter => 'uid=' . $self->{'arg'}->{'user'},
        attrs  => [ '*', 'nsAccountLock' ]
    )
    || return( $self->search( search => $self->{'arg'}->{'user'} ) );

    for ( @{$user->{'objectClass'}} ) { $user->{'_objectClass'}->{lc( $_ )} = 1; }
    $self->{'config'}->{'user.posix'} = 0
        unless $user->{'_objectClass'}->{'posixaccount'};

    if ( $self->{'config'}->{'user.posix'} ) {
        # Login shells
        unless ( $self->{'config'}->{'user.posix.loginshell'} ) {
            push @{$self->{'config'}->{'user.posix.loginshell'}}, '/bin/false';
        }
        $user->{'shells'} = $self->{'cgi'}->popup_menu(
            -name    => 'loginShell',
            -class   => 'dropBox',
            -values  => [ sort @{$self->{'config'}->{'user.posix.loginshell'}} ],
            -default => $user->{'loginShell'}
        );

        unless ( $self->{'config'}->{'user.posix.hosts'} eq '0' ) {
            # Hosts
            my ( $host );
            if ( $user->{'host'} ) {
                $user->{'host'} = [ $user->{'host'} ] unless ref $user->{'host'};
                foreach ( @{$user->{'host'}} ) { $host->{1}->{$_} = 1; }
                delete $user->{'host'};
            }

            my $hosts = $self->{'ldap'}->fetch(
                base   => $self->{'config'}->{'ldap.base.host'},
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

            $user->{'hosts'} = $self->{'util'}->wrap(
                container => 'userHosts',
                %{$user}
            );
        }
    }

    # Groups
    my $group = $self->{'ldap'}->fetch(
            base   => $self->{'config'}->{'ldap.Base.Group'},
            filter => 'objectClass=' . $self->{'config'}->{'group.objectClass'},
            attrs  => [ 'cn', 'gidNumber', $self->{'config'}->{'group.memberAttribute'} ]
    );

    $group = { $group->{'cn'} => $group } if $group && $group->{'cn'};

    $group ||= {};

    my ( %labels );
    foreach my $g ( keys %{$group} ) {
        my $uid = $user->{'uid'};

        # Associate labels (CNs) with gidNumbers
        $labels{$group->{$g}->{'gidNumber'}} = $group->{$g}->{'cn'}
            if $group->{$g}->{'gidNumber'};

        if ( $group->{$g}->{$self->{'config'}->{'group.memberAttribute'}} ) {
            $group->{$g}->{$self->{'config'}->{'group.memberAttribute'}} = [ $group->{$g}->{$self->{'config'}->{'group.memberAttribute'}} ]
                if not ref $group->{$g}->{$self->{'config'}->{'group.memberAttribute'}}; 

            foreach ( @{$group->{$g}->{$self->{'config'}->{'group.memberAttribute'}}} ) {
                $group->{1}->{$group->{$g}->{'cn'}} = 1 if /uid=$uid,/;
            }
        }

        $group->{0}->{$group->{$g}->{'cn'}} = 1
            unless $group->{1}->{$group->{$g}->{'cn'}};
    }

    # Default gidNumber
    if ( $self->{'config'}->{'user.posix'} ) {
        $user->{'groups'} = $self->{'cgi'}->popup_menu(
            -name    =>  'gidNumber',
            -class   => 'dropBox',
            -values  => [ sort { $labels{$a} cmp $labels{$b} } keys %labels ],
            -default => $user->{'gidNumber'},
            -labels  => \%labels,
        );
    }

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

    # Base
    if ( ref $self->{'config'}->{'ldap.base.user'} ) {
        $user->{'base'} = $1 if $user->{'dn'} =~ /^uid=$user->{'uid'}\,\s*(.*)$/;

        my $labels = $self->{'ldap'}->getLabels(
            base => $self->{'config'}->{'ldap.base.user'}
        );

        $user->{'bases'} = $self->{'cgi'}->popup_menu(
            -name    => 'base',
            -class   => 'dropBox',
            -values  => [ sort {
                            $labels->{$a} cmp $labels->{$b}
                        } keys %{$labels} ],
            -default => $user->{'base'},
            -labels  => $labels
        );
    }
    else {
        $user->{'bases'} = $self->{'cgi'}->popup_menu(
            -name    => 'base',
            -class   => 'dropBox',
            -values  => [ 'Users' ]
       );
    }

    # Rename, enable/disable, & delete buttons
    foreach my $function ( qw/ rename disable delete / ) {
        if ( $self->{'config'}->{'user.allow' . $function} eq '1' ) {
            my ( $container );

            if ( $function eq 'disable' ) {
                $container = 'user' . (
                    $user->{'nsAccountLock'}
                        ? 'Enable'
                        : 'Disable'
                );
            }
            else {
                $container = 'user' . ucfirst( $function );
            }

            $user->{$function} = $self->{'util'}->wrap(
                container => $container,
                %{$user}
            );
        }
    }

    if ( $user->{'nsAccountLock'} ) {
        $user->{'error'} = $self->{'util'}->wrap(
            container => 'error',
            error     => 'This account has been disabled.'
        );
    }

    if ( $self->{'arg'}->{'error'} ) {
        $user->{'error'} .= $self->{'util'}->wrap(
            container => 'error',
            error     => $self->{'arg'}->{'error'}
        );
    }

    # Extra attributes
    if ( $self->{'config'}->{'user.extraattributes'} ) {
        unless ( ref $self->{'config'}->{'user.extraattributes'} ) {
            $self->{'config'}->{'user.extraattributes'} =
                [ $self->{'config'}->{'user.extraattributes'} ];
        }

        while ( @{$self->{'config'}->{'user.extraattributes'}} ) {
            my $attribute = shift @{$self->{'config'}->{'user.extraattributes'}};
            $user->{'extra'} .= $self->{'util'}->wrap(
                container => 'userExtra',
                attribute => $attribute,
                value     => $user->{$attribute} || ''
            );
        }
    }

    # Render
    if ( $self->{'config'}->{'user.posix'} ) {
        return( $self->{'util'}->wrapAll( container => 'user', %{$user} ) );
    }
    else {
        return( $self->{'util'}->wrapAll( container => 'userNonPOSIX', %{$user} ) );
    }
}

sub modGroup {
    my $self = shift;

    foreach my $attr ( qw/ description gidNumber / ) {
        unless ( $self->{'arg'}->{$attr} eq $self->{'arg'}->{$attr . 'Was'} ) {
            $self->{'ldap'}->modify(
                'cn=' . $self->{'arg'}->{'group'} . ','
                      . $self->{'config'}->{'ldap.base.group'},
                replace => { $attr => $self->{'arg'}->{$attr} }
            );

            $self->{'arg'}->{$attr . 'Was'} ||= 'null';

            $self->{'util'}->log(
                what   => 'g:' . $self->{'arg'}->{'group'},
                item   => $attr,
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

    # Are we changing bases?
    if (
        ( $self->{'arg'}->{'base'} && $self->{'arg'}->{'baseWas'} ) &&
        ( $self->{'arg'}->{'base'} ne $self->{'arg'}->{'baseWas'} )
    ) {
        # Move the person object
        $self->{'ldap'}->move(
            dn    => $self->{'arg'}->{'dn'},
            base  => $self->{'arg'}->{'base'}
        );

        # Fix group membership
        my $group = $self->{'ldap'}->fetch(
            base   => $self->{'config'}->{'ldap.Base.Group'},
            filter => $self->{'config'}->{'group.memberAttribute'} .'=' . $self->{'arg'}->{'dn'},
            attrs  => [ 'cn' ]
        );

        if ( $group ) {
            $group = { 'g' => $group } if $group->{'cn'};

            foreach my $g ( keys %{$group} ) {
                $self->{'ldap'}->modify(
                    'cn=' . $group->{$g}->{'cn'} . ','
                          . $self->{'config'}->{'ldap.Base.Group'},
                    add    => { $self->{'config'}->{'group.memberAttribute'} => 'uid='
                                  . $self->{'arg'}->{'user'}
                                  . ',' . $self->{'arg'}->{'base'} },
                    delete => { $self->{'config'}->{'group.memberAttribute'} => $self->{'arg'}->{'dn'} }
                );
                if ( $self->{'config'}->{'group.POSIX'} ) {
                    $self->{'ldap'}->modify(
                        'cn=' . $group->{$g}->{'cn'} . ','
                              . $self->{'config'}->{'ldap.Base.Group'},
                        add    => { 'memberUid' =>  $self->{'arg'}->{'user'} },
                        delete => { 'memberUid' => $self->{'arg'}->{'user'} }
                    );
                }
            }
        }

        $self->{'arg'}->{'dn'} =
            'uid=' . $self->{'arg'}->{'user'} . ',' . $self->{'arg'}->{'base'};
    }

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
                            $self->{'arg'}->{'dn'},
                            $action => { 'host' => $obj }
                        );

                        $self->{'util'}->log(
                            what   => 'u:' . $self->{'arg'}->{'user'},
                            item   => 'host',
                            object => $obj,
                            action => $action
                        ) if $self->{'audit'};
                    };

                    /group/ and do {
                        $self->{'ldap'}->modify(
                            'cn=' . $obj . ','
                                  . $self->{'config'}->{'ldap.base.group'},
                            $action => {
                                $self->{'config'}->{'group.memberAttribute'} => $self->{'arg'}->{'dn'}
                            }
                        );
                        if ( $self->{'config'}->{'group.POSIX'} ) {
                            $self->{'ldap'}->modify(
                                'cn=' . $obj . ','
                                  . $self->{'config'}->{'ldap.Base.Group'},
                             $action => {
                                    'memberUid' => $self->{'arg'}->{'user'}
                                }
                            );
                        }

                        $self->{'util'}->log(
                            what   => 'u:' .  $self->{'arg'}->{'user'},
                            item   => 'group',
                            object => $obj,
                            action => $action,
                        ) if $self->{'audit'};
                    };
                };
            }
        }
    }

    my ( @attributes );
    
    @attributes = qw/ cn gidNumber homeDirectory loginShell mail uidNumber /;

    # Extra attributes
    if ( $self->{'config'}->{'user.extraattributes'} ) {
        unless ( ref $self->{'config'}->{'user.extraattributes'} ) {
            $self->{'config'}->{'user.extraattributes'} =
                [ $self->{'config'}->{'user.extraattributes'} ];
        }

        push @attributes, @{$self->{'config'}->{'user.extraattributes'}};
    }
    foreach my $attr ( @attributes ) {
        next unless $self->{'arg'}->{$attr};

        unless ( $self->{'arg'}->{$attr} eq $self->{'arg'}->{$attr . 'Was'} ) {
            if ( $attr eq 'cn' ) {
                my ( $chg );

                $chg->{'cn'} = $self->{'arg'}->{'cn'};

                $chg->{'sn'} = $self->{'arg'}->{'cn'};
                $chg->{'sn'} =~ s/^.+?(\w+)$/$1/;

                $chg->{'givenName'} = $self->{'arg'}->{'cn'};
                $chg->{'givenName'} =~ s/^(\w+).+?$/$1/;

                if ( $self->{'config'}->{'user.posix'} ) {
                    $chg->{'gecos'} = $self->{'arg'}->{'cn'};
                }

                foreach ( keys %{$chg} ) {
                    print Dumper $self->{'ldap'}->modify(
                        $self->{'arg'}->{'dn'},
                        replace => { $_ => $chg->{$_} }
                    );
                }
            }
            else {
                my ( $action );

                $self->{'arg'}->{$attr . 'Was'} eq ''
                    ? $action = 'add'
                    : $action = 'replace';

                $self->{'ldap'}->modify(
                    $self->{'arg'}->{'dn'},
                    $action => { $attr => $self->{'arg'}->{$attr} }
                );
            }

            $self->{'arg'}->{$attr . 'Was'} ||= 'null';

            $self->{'util'}->log(
                what   => 'u:' . $self->{'arg'}->{'user'},
                item   => $attr,
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
            return( $self->displayCreate(
                error => qq(Please enter a username and name.)
            ) )
                unless ( $self->{'arg'}->{'uid'} && $self->{'arg'}->{'cn'} );

            return( $self->displayCreate(
                error => qq(Usernames can contain only alphanumeric characters.)
            ) )
                unless ( $self->{'arg'}->{'uid'} =~ /^\w+$/ );

 
            # Check for existing uniqueID
            if ( $self->{'ldap'}->fetch(
                base   => $self->{'config'}->{'ldap.base.user'},
                filter => $self->{'config'}->{'user.uniqueid'}  . '='
                        . $self->{'arg'}->{$self->{'config'}->{'user.uniqueid'}},
                attrs  => [ 'dn' ]
            ) ) {
                return( $self->displayCreate(
                    error =>
                        qq(<a href="?user=$self->{'arg'}->{'uid'}">)
                      . qq(User ')
                      . $self->{'arg'}->{$self->{'config'}->{'user.uniqueid'}}
                      . qq(' already exists!)
                      . qq(</a>)
                ) )
            }

            $self->{'arg'}->{'user'} = $self->{'arg'}->{'uid'};

            $create->{'dn'} = 'uid=' . $self->{'arg'}->{'uid'} . ',';

            $create->{'dn'} .= $self->{'arg'}->{'base'}
                ? $self->{'arg'}->{'base'}
                : $self->{'config'}->{'ldap.base.user'};

            $create->{'attr'}->{'cn'} = $self->{'arg'}->{'cn'};

            $create->{'attr'}->{'sn'} = $create->{'attr'}->{'cn'};
            $create->{'attr'}->{'sn'} =~ s/^.+?([a-zA-Z\-]+)$/$1/;

            $create->{'attr'}->{'givenName'} = $create->{'attr'}->{'cn'};
            $create->{'attr'}->{'givenName'} =~ s/^([a-zA-Z\-]+).+?$/$1/;

            $create->{'attr'}->{'uid'} = $self->{'arg'}->{'uid'};

            $create->{'attr'}->{'mail'} = $self->{'arg'}->{'mail'}
                if $self->{'arg'}->{'mail'};

            if (
                $self->{'config'}->{'mail.format'} && !$create->{'attr'}->{'mail'}
            ) {
                $create->{'attr'}->{'mail'} = $self->{'config'}->{'mail.format'};

                foreach ( qw/ sn givenName uid / ) {
                    $create->{'attr'}->{'mail'}
                        =~ s/\%$_/$create->{'attr'}->{$_}/g;
                }
            }

            $create->{'attr'}->{'objectClass'} = [ qw/
                top
                person
                organizationalPerson
                inetOrgPerson
            / ];

            if ( $self->{'config'}->{'user.objectclass'} ) {
                push @{$create->{'attr'}->{'objectClass'}},
                    @{$self->{'config'}->{'user.objectclass'}};
            }


            if ( $self->{'config'}->{'user.posix'} ) {
                $create->{'attr'}->{'gecos'} = $self->{'arg'}->{'cn'};
                $self->{'config'}->{'user.posix.homedir.prefix'} ||= '/home/';
                $self->{'config'}->{'user.posix.homedir.prefix'} .= '/' unless /\/$/;
                $create->{'attr'}->{'homeDirectory'} =
                    $self->{'config'}->{'user.posix.homedir.prefix'} . $self->{'arg'}->{'uid'};

                $create->{'attr'}->{'uidNumber'} = $self->{'ldap'}->getNextNum(
                    base => $self->{'config'}->{'ldap.base.user'},
                    unit => 'uid'
                );

                $self->{'config'}->{'user.posix.gid.default'} ||= '100';
                $create->{'attr'}->{'gidNumber'}
                    = $self->{'config'}->{'user.posix.gid.default'};

                $self->{'config'}->{'user.posix.loginshell.default'} ||= '/bin/false';
                $create->{'attr'}->{'loginShell'}
                    = $self->{'config'}->{'user.posix.loginshell.default'};

                push @{$create->{'attr'}->{'objectClass'}}, 'posixAccount'
                    unless grep {
                        $_ eq 'posixAccount'
                    } @{$self->{'config'}->{'user.objectclass'}};

                push @{$create->{'attr'}->{'objectClass'}}, 'account'
                    unless ( $self->{'config'}->{'user.posix.hosts'} eq '0' );
            }

            if (
                $self->{'config'}->{'user.generatepassword'} ||
                (
                    $self->{'config'}->{'mail.welcomeletter'}  &&
                    $self->{'arg'}->{'mail.WelcomeLetter'}
                )
            ) {
                for ( 1..10 ) {
                    $create->{'password'} .= ( 0..9, 'A'..'Z', 'a'..'z')[rand 62];
                }

                $create->{'attr'}->{'userPassword'} = $self->{'util'}->pwEncrypt(
                    text   => $create->{'password'},
                    digest => $self->{'config'}->{'pw.encrypt'}
                )
            }
        };

        /group/ && do {
            return( $self->displayCreate(
                error => qq(Pleaes enter a group name and description.)
            ) )
                unless ( $self->{'arg'}->{'cn'} && $self->{'arg'}->{'description'} );

            # Check for existing group
            if ( $self->{'ldap'}->fetch(
                base   => $self->{'config'}->{'ldap.base.group'},
                filter => 'cn=' . $self->{'arg'}->{'cn'},
                attrs  => [ 'dn' ]
            ) ) {
                return( $self->displayCreate(
                    error =>
                        qq(<a href="?group=$self->{'arg'}->{'cn'}">)
                      . qq(Group ')
                      . $self->{'arg'}->{'cn'}
                      . qq(' already exists!)
                      . qq(</a>)
                ) )
            }

           $self->{'arg'}->{'group'} = $self->{'arg'}->{'cn'};

            $create->{'dn'} = 'cn=' . $self->{'arg'}->{'cn'} . ','
                . $self->{'config'}->{'ldap.base.group'};

            $create->{'attr'}->{'cn'}          = $self->{'arg'}->{'cn'};
            $create->{'attr'}->{'description'} = $self->{'arg'}->{'description'};

            $create->{'attr'}->{'objectClass'} = [
                'top', $self->{'config'}->{'group.objectclass'}
            ];

            if ( $self->{'config'}->{'group.objectclass'} ) {
                push @{$create->{'attr'}->{'objectClass'}},
                    $self->{'config'}->{'group.objectclass'}
                        unless grep {
                            $_ eq $self->{'config'}->{'group.objectclass'}
                        } @{$create->{'attr'}->{'objectClass'}};
            }

            # Populate with a blank uniqueMember for OpenLDAP
            if ( $self->{'config'}->{'group.memberAttribute'} eq 'uniqueMember' ) {
                $create->{'attr'}->{$self->{'config'}->{'group.memberAttribute'}} = '';
            }

            if ( $self->{'config'}->{'group.posix'} ) {
                push @{$create->{'attr'}->{'objectClass'}}, 'posixGroup'
                    unless grep {
                        $_ eq 'posixGroup'
                    } @{$create->{'attr'}->{'objectClass'}};

                $create->{'attr'}->{'gidNumber'} = $self->{'ldap'}->getNextNum(
                    base => $self->{'config'}->{'ldap.base.group'},
                    unit => 'gid'
                );
            }
        };
    }

    my $result =  $self->{'ldap'}->add(
        $create->{'dn'}, attr => [ %{$create->{'attr'}} ]
    );

    if ( $result->code() ) {
        my $error = $result->error();

        for ( $error ) {
            /No such object/ && do {
                my ( $base );

                for ( $self->{'arg'}->{'create'} ) {
                    /user/  && do { $base = $self->{'config'}->{'ldap.base.user'}; };
                    /group/ && do { $base = $self->{'config'}->{'ldap.base.group'}; };
                    
                    $error .= qq( (could not find '$base') );
                }
            };
        }

        return( $self->displayCreate(
            error => 'LDAP error: ' . $error
          ) )
    }

    for ( $self->{'arg'}->{'create'} ) {
        /user/ && do {
            $self->{'util'}->log(
                what   => 'u:' .  $self->{'arg'}->{'user'},
                action => 'create'
            ) if $self->{'audit'};

            if (
                $self->{'config'}->{'mail.welcomeletter'} &&
                $self->{'arg'}->{'mail.WelcomeLetter'}
            ) {
                my $message = $self->{'util'}->wrap(
                    container => $self->{'config'}->{'mail.WelcomeLetter.template'},
                    cn        => $self->{'arg'}->{'cn'},
                    uid       => $self->{'arg'}->{'uid'},
                    password  => $create->{'password'}
                );

                $self->{'config'}->{'mail.welcomeletter.from'} 
                    ||= 'noreply';
                $self->{'config'}->{'mail.welcomeletter.subject'}
                    ||= 'A new account has been created for you!';

                use MIME::Lite;

                {
                    local $ENV{'PATH'} = '';

                    my $email = MIME::Lite->new(
                        From    => $self->{'config'}->{'mail.welcomeletter.from'},
                        To      => $create->{'attr'}->{'mail'},
                        Subject => $self->{'config'}->{'mail.welcomeletter.subject'},
                        Data    => $message 
                    );

                    $email->send();
                }
            }

            return( $self->displayUser() );
        };

        /group/ && do {
            $self->{'util'}->log(
                what   => 'g:' .  $self->{'arg'}->{'group'},
                action => 'create'
            ) if $self->{'audit'};

            return( $self->displayGroup() );
        };
    }
}

sub delete {
    my $self = shift;

    return( $self->displayUser() ) unless $self->{'arg'}->{'dn'};

##
    unless ( $self->{'config'}->{'user.allowdelete'} eq '1' ) {
        $self->{'arg'}->{'error'} = 'You are not allowed to delete users!';

        return( $self->displayUser() );
    }
##

    if ( $self->{'arg'}->{'user'} ) {
        $self->{'ldap'}->delete( $self->{'arg'}->{'dn'} );
    
        my $filter = $self->{'config'}->{'group.memberAttribute'} .  '=' . $self->{'arg'}->{'dn'};

        my $group = $self->{'ldap'}->fetch(
            base   => $self->{'config'}->{'ldap.base.group'},
            filter => $filter,
            attrs  => [ 'cn' ]
        );

        if ( $group ) {
            $group = { 'g' => $group } if $group->{'cn'};

            foreach my $g ( keys %{$group} ) {
                $self->{'ldap'}->modify(
                    'cn=' . $group->{$g}->{'cn'} . ','
                          . $self->{'config'}->{'ldap.Base.Group'},
                    delete => { $self->{'config'}->{'group.memberAttribute'} => $self->{'arg'}->{'dn'} }
                );
                if ( $self->{'config'}->{'group.POSIX'} ) {
                    $self->{'ldap'}->modify(
                        'cn=' . $group->{$g}->{'cn'} . ','
                              . $self->{'config'}->{'ldap.Base.Group'},
                        delete => {
                            'memberUid' => $self->{'arg'}->{'user'}
                        }
                    );
                }
            }
        }

        $self->{'util'}->log(
            what   => 'u:' .  $self->{'arg'}->{'user'},
            action => 'delete'
        ) if $self->{'audit'};

        delete $self->{'arg'}->{'user'};
    }

    if ( $self->{'arg'}->{'group'} ) {
        $self->{'ldap'}->delete(
            'cn=' . $self->{'arg'}->{'group'} . ','
                  . $self->{'config'}->{'ldap.base.group'}
        );

        $self->{'util'}->log(
            what   => 'g:' .  $self->{'arg'}->{'group'},
            action => 'delete'
        ) if $self->{'audit'};

        delete $self->{'arg'}->{'group'};
    }

    return( $self->displaySearch() );
}

sub disable {
    my $self = shift;

    return( $self->displayUser() ) unless $self->{'arg'}->{'dn'};

    $self->{'ldap'}->modify(
        $self->{'arg'}->{'dn'},
        add => { 'nsAccountLock' => 'true' }
    );

    $self->{'util'}->log(
        what   => 'u:' . $self->{'arg'}->{'user'},
        action => 'disable'
    ) if $self->{'audit'};

    return( $self->displayUser() );
}

sub enable {
    my $self = shift;

    return( $self->displayUser() ) unless $self->{'arg'}->{'dn'};

    $self->{'ldap'}->modify(
        $self->{'arg'}->{'dn'},
        delete => { 'nsAccountLock' => 'true' }
    );

    $self->{'util'}->log(
        what   => 'u:' . $self->{'arg'}->{'user'},
        action => 'enable'
    ) if $self->{'audit'};

    return( $self->displayUser() );
}

sub password {
    my $self = shift;

    return( $self->displayUser() ) unless (
        $self->{'arg'}->{'dn'} && $self->{'arg'}->{'password'}
    );

    my $pwCrypt = $self->{'util'}->pwEncrypt(
        text   => $self->{'arg'}->{'password'},
        digest => $self->{'config'}->{'pw.encrypt'}
    )
    || die qq(Error attempting to encrypt password\n);

    $self->{'ldap'}->modify(
        $self->{'arg'}->{'dn'},
        replace => { userPassword => $pwCrypt }
    );

    $self->{'util'}->log(
        what   => 'u:' .  $self->{'arg'}->{'user'},
        action => 'password modify'
    ) if $self->{'audit'};

    return( $self->displayUser() );
}

sub rename {
    my $self = shift;

    # Move the user
    unless (
        $self->{'ldap'}->move(
            dn      => $self->{'arg'}->{'dn'},
            base    => $self->{'arg'}->{'base'},
            newuser => $self->{'arg'}->{'newuser'}
        )
    ) {
        $self->{'arg'}->{'error'} = 'The specified username already exists.';

        return( $self->displayUser() );
    }

    $self->{'util'}->log(
        what   => 'u:' . $self->{'arg'}->{'newuser'},
        item   => 'user',
        object => '(was ' . $self->{'arg'}->{'user'} . ')',
        action => 'move'
    ) if $self->{'audit'};
 
    $self->{'arg'}->{'user'} = $self->{'arg'}->{'newuser'};

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

    my ( $base );
    if ( !$self->{'arg'}->{'base'} || $self->{'arg'}->{'base'} eq '' ) {
        $base = undef;
    }
    else {
        $base = $self->{'arg'}->{'base'};
    }

    my ( $user, $group );

    if ( $self->{'arg'}->{'search'} eq '*' ) {
        $user = $self->{'ldap'}->fetch(
            base   => $base || $self->{'config'}->{'ldap.base.user'},
            filter => '(uid=*)',
            attrs  => [ '*', 'nsAccountLock' ]
        ) || {};
        $group = $self->{'ldap'}->fetch(
            base   => $base || $self->{'config'}->{'ldap.base.group'},
            filter =>
                '(& (objectClass=' . $self->{'config'}->{'group.objectclass'} . ')'
                 . '(cn=*) )',
            attrs  => [ '*' ]
        ) || {};
    }
    else {
        $user = $self->{'ldap'}->fetch(
            base   => $base || $self->{'config'}->{'ldap.base.user'},
            filter =>
                '(| (uid=*' . $self->{'arg'}->{'search'} . '*)'
                 . '(mail=*' . $self->{'arg'}->{'search'} . '*)'
                 . '(cn=*' . $self->{'arg'}->{'search'} . '*) )',
            attrs  => [ '*', 'nsAccountLock' ]
        ) || {};
        $group = $self->{'ldap'}->fetch(
            base   => $base || $self->{'config'}->{'ldap.base.group'},
            filter =>
                '(& (objectClass=' . $self->{'config'}->{'group.objectclass'} . ')'
                 . '(cn=*' . $self->{'arg'}->{'search'} . '*) )',
            attrs  => [ '*' ]
        ) || {};
    }

    $user  = { 'u' => $user }  if $user->{'uid'};
    $group = { 'g' => $group } if $group->{'cn'};

    my $search = { %{$user}, %{$group} };

    unless ( keys %{$search} ) {
        return( $self->displaySearch(
            error => qq(No matches for '$self->{'arg'}->{'search'}' found.)
        ) );
    }

    # Return a list
    return( $self->{'util'}->wrapAll(
        container => 'results',
        search    => $self->{'arg'}->{'search'},
        results   => sub {
            my ( $results );

            $results = '<table>';

            my $c = 0;
            foreach my $i ( sort keys %{$search} ) {
                my $type = $search->{$i}->{'uid'} ? 'user' : 'group';

                $results .= $self->{'util'}->wrap(
                    container => 'resultsItemExt',
                    eo        => sub {
                        if ( $c % 2 ) { return( 'odd' ); } else { return( 'even' ); }
                    },
                    item      => $search->{$i}->{'uid'} || $search->{$i}->{'cn'},
                    itemType  => $type,
                    itemDesc  => $search->{$i}->{'description'}
                              || $search->{$i}->{'cn'} || '?',
                    itemDesc2 => $search->{$i}->{'mail'},
                    itemDesc3 => sub {
                        return( 'Disabled' ) if $search->{$i}->{'nsAccountLock'} || '';
                    }
                );

                $c++;
            }

            $results .= '</table>';

            return( $results );
        },
        total     => scalar keys %{$search},
        base      => sub {
            unless ( ref $self->{'config'}->{'ldap.base.user'} ) {
                return( '' );
            }

            my $labels = $self->{'ldap'}->getLabels(
                base => $self->{'config'}->{'ldap.base.user'}
            );

            $labels->{''} = ' All ';

            return( $self->{'cgi'}->popup_menu(
                -name   => 'base',
                -class  => 'dropBox',
                -values => [ sort {
                                $labels->{$a} cmp $labels->{$b}
                            } keys %{$labels} ],
                -labels => $labels
            ) );
        }
    ) );
}

1;
