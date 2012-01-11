package Authen::PAM::Module::test;

use strict;
use warnings;
use Authen::PAM::Module;
use Carp;

our @ISA = qw(Authen::PAM::Module);

sub authenticate {
	my $self=shift;
	print $self->{user}."\n";
	my @ret=$self->conv(
		[PROMPT_ECHO_ON=>"test:"],
		[PROMPT_ECHO_ON=>"test:"],
		[PROMPT_ECHO_OFF=>"test:"],
		[ERROR_MSG=>"test:"],
		[TEXT_INFO=>"test:"],
	);
	print "@ret\n";
	print join ' ',map {$_+0} @ret;
	print "\n";
	warn;
	#return "SUCCESS";
	return "IGNORE";
}
1;
