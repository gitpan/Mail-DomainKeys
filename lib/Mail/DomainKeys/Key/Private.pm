# Copyright (c) 2004 Anthony D. Urso. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Mail::DomainKeys::Key::Private;

use base "Mail::DomainKeys::Key";

use strict;

our $VERSION = "0.14";

sub load {
	my $type = shift;
	my %prms = @_;
	my $self = {};


	$self->{'TYPE'} = ($prms{'Type'} or "rsa");

	if ($prms{'Data'}) {
		$self->{'DATA'} = $prms{'Data'};
	} elsif ($prms{'File'}) {	
		my @data;
		open FILE, "<$prms{'File'}" or
			return;
		while (<FILE>) {
			chomp;
			/^---/ and
				next;
			push @data, $_;
		}
		$self->{'DATA'} = join '', @data;
	} else {
		return;
	}

	bless $self, $type;
}

sub convert {
	use Crypt::OpenSSL::RSA;

	my $self = shift;


	$self->data or
		return;

	# have to PKCS1ify the privkey because openssl is too finicky...
	my $pkcs = "-----BEGIN RSA PRIVATE KEY-----\n";

	for (my $i = 0; $i < length $self->data; $i += 64) {
		$pkcs .= substr $self->data, $i, 64;
		$pkcs .= "\n";
	}	

	$pkcs .= "-----END RSA PRIVATE KEY-----\n";

	my $cork = new_private_key Crypt::OpenSSL::RSA($pkcs);

#	$cork->check_key or
#		return;

	$self->cork($cork);

	return 1;
}

sub sign {
	my $self = shift;
	my $mail = shift;


	return $self->cork->sign($mail);
}

1;
