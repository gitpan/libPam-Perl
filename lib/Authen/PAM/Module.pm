package Authen::PAM::Module;

use 5.010001;
#use strict;
use warnings;
#use Authen::PAM::Module::_user;
#use Authen::PAM::Module::_env;
#use Authen::PAM::Module::_item;
use Carp;

require Exporter;
use AutoLoader;

our @ISA = qw(Exporter);
our %EXPORT_TAGS = (
	data=>[qw(
		PAM_DATA_REPLACE PAM_DATA_SILENT PAM_BUF_ERR PAM_SUCCESS
		PAM_SYSTEM_ERR PAM_NO_MODULE_DATA
	)],
	item=>[qw(
		PAM_SERVICE PAM_USER PAM_USER_PROMPT PAM_TTY PAM_RUSER PAM_RHOST
		PAM_AUTHTOK PAM_OLDAUTHTOK PAM_CONV PAM_FAIL_DELAY PAM_XDISPLAY
		PAM_XAUTHDATA PAM_AUTHTOK_TYPE PAM_BAD_ITEM PAM_BUF_ERR
		PAM_SUCCESS PAM_SYSTEM_ERR PAM_PERM_DENIED
	)],
	user=>[qw(PAM_SUCCESS PAM_SYSTEM_ERR PAM_CONV_ERR)],
	conv=>[qw(
		PAM_PROMPT_ECHO_OFF PAM_PROMPT_ECHO_ON PAM_ERROR_MSG
		PAM_TEXT_INFO PAM_BUF_ERR PAM_CONV_ERR PAM_SUCCESS
	)],
	env=>[qw(PAM_PERM_DENIED PAM_BAD_ITEM PAM_ABORT PAM_BUF_ERR PAM_SUCCESS)],
	auth=>[qw(
		PAM_SILENT PAM_DISALLOW_NULL_AUTHTOK PAM_AUTH_ERR
		PAM_CRED_INSUFFICIENT PAM_AUTHINFO_UNAVAIL PAM_SUCCESS
		PAM_USER_UNKNOWN PAM_MAXTRIES PAM_ESTABLISH_CRED PAM_DELETE_CRED
		PAM_REINITIALIZE_CRED PAM_REFRESH_CRED PAM_CRED_UNAVAIL
		PAM_CRED_EXPIRED PAM_CRED_ERR
	)],
	acct=>[qw(
		PAM_SILENT PAM_DISALLOW_NULL_AUTHTOK PAM_ACCT_EXPIRED
		PAM_AUTH_ERR PAM_NEW_AUTHTOK_REQD PAM_PERM_DENIED PAM_SUCCESS
		PAM_USER_UNKNOWN
	)],
	sess=>[qw(PAM_SILENT PAM_SESSION_ERR PAM_SUCCESS)],
	pass=>[qw(
		PAM_SILENT PAM_CHANGE_EXPIRED_AUTHTOK PAM_PRELIM_CHECK
		PAM_UPDATE_AUTHTOK PAM_AUTHTOK_ERR PAM_AUTHTOK_RECOVERY_ERR
		PAM_AUTHTOK_LOCK_BUSY PAM_AUTHTOK_DISABLE_AGING PAM_PERM_DENIED
		PAM_TRY_AGAIN PAM_SUCCESS
	)],
	misc=>[qw(strerr fail_delay PAM_SUCCESS PAM_SYSTEM_ERR)],
	other=>[qw(
		PAM_BINARY_PROMPT
		PAM_AUTHTOK_EXPIRED
		PAM_CONV_AGAIN
		PAM_IGNORE
		PAM_INCOMPLETE
		PAM_MAX_MSG_SIZE
		PAM_MAX_NUM_MSG
		PAM_MAX_RESP_SIZE
		PAM_MODULE_UNKNOWN
		PAM_OPEN_ERR
		PAM_RADIO_TYPE
		PAM_SERVICE_ERR
		PAM_SYMBOL_ERR
		_PAM_RETURN_VALUES
		__LINUX_PAM_MINOR__
		__LINUX_PAM__
	)]
);

our @EXPORT = qw();
our @EXPORT_OK = map {@{$EXPORT_TAGS{$_}}} keys %EXPORT_TAGS;
$EXPORT_TAGS{all}=\@EXPORT_OK;


our $VERSION = '0.003';

sub AUTOLOAD {
	# This AUTOLOAD is used to 'autoload' constants from the constant()
	# XS function.

	my $constname;
	our $AUTOLOAD;
	($constname = $AUTOLOAD) =~ s/.*:://;
	warn  "&Authen::PAM::Module::constant not defined ($AUTOLOAD)" if $constname eq 'constant';
	croak "&Authen::PAM::Module::constant not defined" if $constname eq 'constant';
	my ($error, $val) = constant($constname);
	if ($error && $error =~ /is not a valid Authen::PAM::Module macro/) {
		($error, $val) = constant('PAM_'.$constname);
	}
	if ($error) {warn $error; croak $error; }
	{
		no strict 'refs';
		# Fixed between 5.005_53 and 5.005_61
		#XXX if ($] >= 5.00561) {
		#XXX	*$AUTOLOAD = sub () { $val };
		#XXX } else {
			*$AUTOLOAD = sub { $val };
		#XXX }
	}
	goto &$AUTOLOAD;
}

#XXX should we delete next two lines? treat as static?
# can we?
require XSLoader;
XSLoader::load('Authen::PAM::Module', $VERSION);

package Authen::PAM::Module::_err;

sub PRINT {
	my $self = shift;
	$,=''unless defined $,;
	$\=''unless defined $\;
	my @ret=$$self->conv([Authen::PAM::Module::PAM_ERROR_MSG(),join($,,@_).$\]);
}

sub UNTIE {
	my $self = shift;
	$$self=undef;
	warn "@_" if @_;
	return "0 but true";
}

#A class implementing a file handle should have the following methods:
	#TIEHANDLE classname, LIST
	#READ this, scalar, length, offset
	#READLINE this
	#GETC this
	#WRITE this, scalar, length, offset
	#PRINTF this, format, LIST
	#BINMODE this
	#EOF this
	#FILENO this
	#SEEK this, position, whence
	#TELL this
	#OPEN this, mode, LIST
	#CLOSE this
	#DESTROY this

package Authen::PAM::Module::_out;

use Carp;

sub UNTIE {
	my $self = shift;
	$$self=undef;
	warn "@_" if @_;
	return "0 but true";
}

#A class implementing a file handle should have the following methods:
	#TIEHANDLE classname, LIST
	#READ this, scalar, length, offset
	#READLINE this
	#GETC this
	#WRITE this, scalar, length, offset
	#PRINT this, LIST
	#PRINTF this, format, LIST
	#BINMODE this
	#EOF this
	#FILENO this
	#SEEK this, position, whence
	#TELL this
	#OPEN this, mode, LIST
	#CLOSE this
	#DESTROY this

sub PRINT {
	my $self = shift;
	$,=''unless defined $,;
	$\=''unless defined $\;
	my @ret=$$self->conv([Authen::PAM::Module::PAM_TEXT_INFO(),join($,,@_).$\]);
}

package Authen::PAM::Module::_user;

use Carp;

#sub TIESCALAR {my($c,$p)=@_; return bless \$p, $c if($p);}
#sub TIEBAD{	return bless \$_[1], $_[0] if($_[1]);}

sub UNTIE {
	my $self = shift;
	$$self=undef;
	warn "@_" if @_;
	return "0 but true";
}

#A class implementing a scalar should have the following methods:
	#STORE this, value
	#DESTROY this

package Authen::PAM::Module::_item;

use Carp;

sub STORE {
	my $self=shift;
	my $arg=shift;
	my $val=shift;
	my $ret;
	if($arg+0 eq$arg){
		$ret=Authen::PAM::Module::put_item($$self->{pamh},$arg,$val);
	}else{
		$ret=Authen::PAM::Module::put_item($$self->{pamh},Authen::PAM::Module::map_constant($arg),$val);
	}
	return undef if($ret == PAM_BAD_ITEM);
	die unless($ret==PAM_SUCCESS);
	return $val;
}

sub EXISTS {
	shift;my$_=shift;
	return $_&& $_>14 if $_+0 eq$_;
	return 1 if /SERVICE$/i;
	return 1 if /USER$/i;
	return 1 if /TTY$/i;
	return 1 if /RHOST$/i;
	return 1 if /CONV$/i;
	return 1 if /AUTHTOK$/i;
	return 1 if /OLDAUTHTOK$/i;
	return 1 if /RUSER$/i;
	return 1 if /USER_PROMPT$/i;
	return 1 if /FAIL_DELAY$/i;
	return 1 if /XDISPLAY$/i;
	return 1 if /XAUTHDATA$/i;
	return 1 if /AUTHTOK_TYPE$/i;
	return 0 ;
}

sub UNTIE {
	my $self = shift;
	$$self=undef;
	#warn "@_" if @_;
	return "0 but true";
}

#A class implementing a hash should have the following methods:
	#DELETE this, key
	#CLEAR this
	#FIRSTKEY this
	#NEXTKEY this, lastkey
	#SCALAR this
	#DESTROY this

use Carp;
sub DELETE {
	my $self=shift;
	my $arg=shift;
	carp 'Can not delete from list of pam items.';
	return undef;
}

package Authen::PAM::Module::_env;

use Carp;

#A class implementing a hash should have the following methods:
	#CLEAR this
	#FIRSTKEY this
	#NEXTKEY this, lastkey
	#SCALAR this
	#DESTROY this
	#UNTIE this

sub FETCH {
	my $self=shift;
	my $arg=shift;
	return $$self->{internal}{env}{$arg} if defined $$self->{internal}{env}{$arg};
	return $$self->{internal}{env}{$arg}=Authen::PAM::Module::getenv($$self->{pamh},$arg);;
}

sub STORE {
	my $self=shift;
	my $arg=shift;
	$$self->{internal}{env}{$arg}=shift;
	Authen::PAM::Module::putenv($$self->{pamh},"$arg=".$$self->{internal}{env}{$arg});
	return $$self->{internal}{env}{$arg};
}

sub DELETE {
	my $self=shift;
	my $arg=shift;
	$$self->{internal}{env}{$arg}=undef;
	Authen::PAM::Module::putenv($$self->{pamh},"$arg");
	return $$self->{internal}{env}{$arg};
}

sub EXISTS {
	return defined FETCH @_;
}

sub UNTIE {
	my $self = shift;
	my $count = shift;

	confess "wrong type" unless ref $self;
	carp "untie attempted while $count inner references still exist" if $count;
	$$self=undef;
	warn "@_" if @_;
	return "0 but true";
}

package Authen::PAM::Module;

use Carp;

sub new { # Manditory. Call if overloaded.
	my $invocant = shift;
	my $class = ref($invocant)||$invocant;
	my $self = {pamh=>shift};
	$self->{me}=shift;
	$self->{initial}{flag}=shift;
	$self->{initial}{arg}=[@_];
	#$self->{data}={}; # for private storage by child modules;
	$self->{user_prompt}="user:" unless $self->{user_prompt};
	bless ($self, $class);
	tie $self->{user}, 'Authen::PAM::Module::_user', $self;
	tie %{$self->{env}}, 'Authen::PAM::Module::_env', $self;
	tie %{$self->{item}}, 'Authen::PAM::Module::_item', $self;
	tie *STDERR, 'Authen::PAM::Module::_err', $self;
	tie *STDOUT, 'Authen::PAM::Module::_out', $self;
	return $self;
}

sub DESTROY {
	my $self = shift;
	untie *STDERR;
	untie *STDOUT;
	untie $self->{user};
	untie %{$self->{env}};
	untie %{$self->{item}};
	delete $self->{internal};
	delete $self->{initial};
	delete $self->{item};
	delete $self->{env};
	delete $self->{user};
	delete $self->{pamh};
	delete $self->{me};
	delete $self->{user_prompt};
	warn join ' ', keys %$self if %$self;
	warn "@_" if @_;
	return "0 but true";
}

sub map_constant($){
	my $_=shift;
	s|^[ 	]*||;
	s|[ 	]*$||;
	return Authen::PAM::Module::PAM_CHANGE_EXPIRED_AUTHTOK()	if /CHANGE_EXPIRED_AUTHTOK$/i;
	return Authen::PAM::Module::PAM_AUTHTOK_DISABLE_AGING()	if /AUTHTOK_DISABLE_AGING$/i;
	return Authen::PAM::Module::PAM_DISALLOW_NULL_AUTHTOK()	if /DISALLOW_NULL_AUTHTOK$/i;
	return Authen::PAM::Module::PAM_AUTHTOK_RECOVERY_ERR()	if /AUTHTOK_RECOVERY_ERR$/i;
	return Authen::PAM::Module::PAM_AUTHTOK_LOCK_BUSY()	if /AUTHTOK_LOCK_BUSY$/i;
	return Authen::PAM::Module::PAM_CRED_INSUFFICIENT()	if /CRED_INSUFFICIENT$/i;
	return Authen::PAM::Module::PAM_REINITIALIZE_CRED()	if /REINITIALIZE_CRED$/i;
	return Authen::PAM::Module::PAM_AUTHINFO_UNAVAIL()	if /AUTHINFO_UNAVAIL$/i;
	return Authen::PAM::Module::PAM_NEW_AUTHTOK_REQD()	if /NEW_AUTHTOK_REQD$/i;
	return Authen::PAM::Module::PAM_AUTHTOK_EXPIRED()	if /AUTHTOK_EXPIRED$/i;
	return Authen::PAM::Module::PAM_PROMPT_ECHO_OFF()	if /PROMPT_ECHO_OFF$/i;
	return Authen::PAM::Module::PAM_ESTABLISH_CRED()	if /ESTABLISH_CRED$/i;
	return Authen::PAM::Module::PAM_MODULE_UNKNOWN()	if /MODULE_UNKNOWN$/i;
	return Authen::PAM::Module::PAM_NO_MODULE_DATA()	if /NO_MODULE_DATA$/i;
	return Authen::PAM::Module::PAM_PROMPT_ECHO_ON()	if /PROMPT_ECHO_ON$/i;
	return Authen::PAM::Module::PAM_UPDATE_AUTHTOK()	if /UPDATE_AUTHTOK$/i;
	return Authen::PAM::Module::PAM_BINARY_PROMPT()	if /BINARY_PROMPT$/i;
	return Authen::PAM::Module::PAM_ACCT_EXPIRED()	if /ACCT_EXPIRED$/i;
	return Authen::PAM::Module::PAM_AUTHTOK_TYPE()	if /AUTHTOK_TYPE$/i;
	return Authen::PAM::Module::PAM_CRED_EXPIRED()	if /CRED_EXPIRED$/i;
	return Authen::PAM::Module::PAM_CRED_UNAVAIL()	if /CRED_UNAVAIL$/i;
	return Authen::PAM::Module::PAM_DATA_REPLACE()	if /DATA_REPLACE$/i;
	return Authen::PAM::Module::PAM_PRELIM_CHECK()	if /PRELIM_CHECK$/i;
	return Authen::PAM::Module::PAM_REFRESH_CRED()	if /REFRESH_CRED$/i;
	return Authen::PAM::Module::PAM_USER_UNKNOWN()	if /USER_UNKNOWN$/i;
	return Authen::PAM::Module::PAM_AUTHTOK_ERR()	if /AUTHTOK_ERR$/i;
	return Authen::PAM::Module::PAM_DATA_SILENT()	if /DATA_SILENT$/i;
	return Authen::PAM::Module::PAM_DELETE_CRED()	if /DELETE_CRED$/i;
	return Authen::PAM::Module::PAM_PERM_DENIED()	if /PERM_DENIED$/i;
	return Authen::PAM::Module::PAM_SERVICE_ERR()	if /SERVICE_ERR$/i;
	return Authen::PAM::Module::PAM_SESSION_ERR()	if /SESSION_ERR$/i;
	return Authen::PAM::Module::PAM_USER_PROMPT()	if /USER_PROMPT$/i;
	return Authen::PAM::Module::PAM_CONV_AGAIN()	if /CONV_AGAIN$/i;
	return Authen::PAM::Module::PAM_FAIL_DELAY()	if /FAIL_DELAY$/i;
	return Authen::PAM::Module::PAM_INCOMPLETE()	if /INCOMPLETE$/i;
	return Authen::PAM::Module::PAM_OLDAUTHTOK()	if /OLDAUTHTOK$/i;
	return Authen::PAM::Module::PAM_RADIO_TYPE()	if /RADIO_TYPE$/i;
	return Authen::PAM::Module::PAM_SYMBOL_ERR()	if /SYMBOL_ERR$/i;
	return Authen::PAM::Module::PAM_SYSTEM_ERR()	if /SYSTEM_ERR$/i;
	return Authen::PAM::Module::PAM_ERROR_MSG()	if /ERROR_MSG$/i;
	return Authen::PAM::Module::PAM_TEXT_INFO()	if /TEXT_INFO$/i;
	return Authen::PAM::Module::PAM_TRY_AGAIN()	if /TRY_AGAIN$/i;
	return Authen::PAM::Module::PAM_XAUTHDATA()	if /XAUTHDATA$/i;
	return Authen::PAM::Module::PAM_AUTH_ERR()	if /AUTH_ERR$/i;
	return Authen::PAM::Module::PAM_BAD_ITEM()	if /BAD_ITEM$/i;
	return Authen::PAM::Module::PAM_CONV_ERR()	if /CONV_ERR$/i;
	return Authen::PAM::Module::PAM_CRED_ERR()	if /CRED_ERR$/i;
	return Authen::PAM::Module::PAM_MAXTRIES()	if /MAXTRIES$/i;
	return Authen::PAM::Module::PAM_OPEN_ERR()	if /OPEN_ERR$/i;
	return Authen::PAM::Module::PAM_XDISPLAY()	if /XDISPLAY$/i;
	return Authen::PAM::Module::PAM_AUTHTOK()	if /AUTHTOK$/i;
	return Authen::PAM::Module::PAM_BUF_ERR()	if /BUF_ERR$/i;
	return Authen::PAM::Module::PAM_SERVICE()	if /SERVICE$/i;
	return Authen::PAM::Module::PAM_SUCCESS()	if /SUCCESS$/i;
	return Authen::PAM::Module::PAM_IGNORE()	if /IGNORE$/i;
	return Authen::PAM::Module::PAM_SILENT()	if /SILENT$/i;
	return Authen::PAM::Module::PAM_ABORT()	if /ABORT$/i;
	return Authen::PAM::Module::PAM_RHOST()	if /RHOST$/i;
	return Authen::PAM::Module::PAM_RUSER()	if /RUSER$/i;
	return Authen::PAM::Module::PAM_CONV()	if /CONV$/i;
	return Authen::PAM::Module::PAM_USER()	if /USER$/i;
	return Authen::PAM::Module::PAM_TTY()	if /TTY$/i;
	return undef;
}
sub intorconst($){
	no warnings 'numeric';
	my $_=shift;
	return $_ if($_+0 eq $_.'');
	return map_constant($_);
}

sub authenticate {
	warn "@_";
	return PAM_IGNORE();
}
sub setcred {
	warn "@_";
	return PAM_IGNORE();
}
sub acct_mgmt {
	warn "@_";
	return PAM_IGNORE();
}
sub open_session {
	warn "@_";
	return PAM_IGNORE();
}
sub close_session {
	warn "@_";
	return PAM_IGNORE();
}
sub chauthtok {
	warn "@_";
	return PAM_IGNORE();
}

1;
__END__

=head1 NAME

Authen::PAM::Module - Base module for writing Pam Modules in Perl

=head1 SYNOPSIS

	package Authen::PAM::Module::xxxxxx;
	use Authen::PAM::Module qw(type type);
	our @ISA=qw(Authen::PAM::Module);

	sub ...
	{
		my $handle=shift;
		my $flags=shift;
		my @args=@_;
		$handle->{item}
		$handle->{user}
		$handle->{env}
		$handle->{data}

=head1 DESCRIPTION

Authen::PAM::Module is a base class to be inhereted by perl modules whishing to function as PAM
(Plugable Authentication Modules) modules.

=head2 paramaters:

The first paramater passed must be the user module name relitave to Authen::PAM::Module::. All paramaters are passed unchanged.

=head2 methods:

Only the following methods are overridable:

	new($class, $pamh, $flags, @args): constructor called from first function call. If you overload it, call it to initilize your tied vars, etc.

	authenticate($handle, $flags, @args):
	setcred($handle, $flags, @args):
	acct_mgmt($handle, $flags, @args):
	open_session($handle, $flags, @args):
	close_session($handle, $flags, @args):
	chauthtok($handle, $flags, @args):
	DESTROY:

The following methods are interfaces to the pam library.

The following are tied vars and other constructs to provide the rest of the api.

	$handle->{data}	for private storage by child modules (pam_set_data, pam get_data equivilent. no access to other modules data)
	$handle->{user}	username, blessed scalar read only
	$handle->{item}	pam items, blessed hash read write
	$handle->{env}	pam envroment, blessed hash read write

general notes: when reading the pam documentation

=head2 EXPORT

None by default.

=head2 Exportable tags

	other this tag has all constants not otherwise classified. If you use one, please let me know so I can file it correctly.
	data  this tag has constants for module private storage. If you need this I made a mistake, please let me know.
	misc  the functions strerr and fail_delay and their constants (linux pam specific).
	item  
	user
	conv
	env
	auth
	acct
	sess
	pass

=head1 HISTORY

=over 8

=item 0.01

Original version; created by h2xs 1.23 and then mangled by hand extensively.

=back



=head1 SEE ALSO

Pam Module Writing Guide.
Authen::PAM

=head1 AUTHOR

Ben Hildred<lt>bhildred@cpan.org<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2011 by Ben Hildred

This library is free software; you can redistribute it under the following conditions:
Until it is fully functional you must maintain this copyright notice, fix at least one
bug, notify all upstream authors of all changes and adhear to all conditions of GNU
GPL 2.0 or later. (Distribution mirrors (i.e. CPAN, Debian nonfree) and mailing lists
are allowed unlimited disribution, provided the poster makes a good faith attempt to adhear)
Once this is fully functional, the previous clause may be droped and you may redistribute
and/or modify it under the same terms as Perl itself, either Perl version 5.10.1 or,
at your option, any later version of Perl 5 you may have available.


=cut
