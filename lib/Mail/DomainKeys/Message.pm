# Copyright (c) 2004 Anthony D. Urso. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Mail::DomainKeys::Message;

use strict;

our $VERSION = "0.80";

sub load {
	use Mail::Address;
	use Mail::DomainKeys::Header;
	use Mail::DomainKeys::Signature;

	my $type = shift;
	my %prms = @_;

	my $self = {};


	my $file;

	if ($prms{'File'}) {
		if (ref $prms{'File'} and ref $prms{'File'} eq "GLOB") {
			$file = $prms{'File'};
		} else {
			return;
		}
	} else {
		$file = \*STDIN;
	}

	my $lnum = 0;

	my @head;

	if ($prms{'HeadString'}) {
		foreach (split /\n/, $prms{'HeadString'}) {
			s/\r$//;
			last if /^$/;
			if (/^\s/ and $head[$lnum-1]) {
				$head[$lnum-1]->append($_);
				next;
			}			
			$head[$lnum] =
				parse Mail::DomainKeys::Header(String => $_);

			$lnum++;
		}
	} else {
		while (<$file>) {
			s/\r$//;
			last if /^$/;
			if (/^\s/ and $head[$lnum-1]) {
				$head[$lnum-1]->append($_);
				next;
			}			
			$head[$lnum] =
				parse Mail::DomainKeys::Header(String => $_);

			$lnum++;
		}
	}

	my %seen = (FROM => 0, SIGN => 0, SNDR => 0);

	foreach my $hdr (@head) {
		$hdr->signed($seen{'SIGN'});

		$hdr->key or
			return;

		if ($hdr->key =~ /^From$/i and !$seen{'FROM'}) {
			my @list = parse Mail::Address($hdr->vunfolded);
			$self->{'FROM'} = $list[0]; 
			$seen{'FROM'} = 1; 
		} elsif ($hdr->key =~ /^Sender$/i and !$seen{'SNDR'}) {
			my @list = parse Mail::Address($hdr->vunfolded);
			$self->{'SNDR'} = $list[0];
			$seen{'SNDR'} = 1;
		} elsif ($hdr->key =~ /^DomainKey-Signature$/i and
			not $seen{'SIGN'}) {
			$self->{'SIGN'} = parse Mail::DomainKeys::Signature(
				String => $hdr->vunfolded);
			$seen{'SIGN'} = 1;
		}
	}

	my @body;

	if ($prms{'BodyReference'}) {
		@body = @{$prms{'BodyReference'}};
	} else {
		while (<$file>) {
			s/\r$//;
			push @body, $_;
		}
	}

	$self->{'HEAD'} = \@head;
	$self->{'BODY'} = \@body;

	bless $self, $type;
}

sub canonify {
	my $self = shift;


	$self->signature->method or
		return;

	$self->signature->method eq "nofws" and
		return $self->nofws;

	$self->signature->method eq "simple" and
		return $self->simple;

	return;
}

sub gethline {
	my $self = shift;
	my $hdrs = shift or
		return;

	my %hmap = map { lc($_) => 1 } (split(/:/, $hdrs));

	my @found = ();
	foreach my $hdr (@{$self->head}) {
		if ($hmap{lc($hdr->key)}) {
			push(@found, $hdr->key);        
			delete $hmap{$hdr->key};
		}
	}

	my $res = join(':', @found);
	return $res;
}

sub nofws {	
	my $self = shift;

	my $text;


	foreach my $hdr (@{$self->head}) {
		$hdr->signed or $self->signature->signing or
			next;
		$self->signature->wantheader($hdr->key) or
			next;
		my $line = $hdr->unfolded;
		$line =~ s/[\s\r\n]//g;
		$text .= $line . "\r\n";
	}

	# delete trailing blank lines
	foreach (reverse @{$self->{'BODY'}}) {
		/[^\s\r\n]/ and # last non-blank line
			last;
		/^[\s\r\n]*$/ and
			pop @{$self->{'BODY'}};
	}

	# make sure there is a body before adding a seperator line
	(scalar @{$self->{'BODY'}}) and
		$text .= "\r\n";

	foreach my $lin (@{$self->{'BODY'}}) {
		$lin =~ s/[\s\r\n]//g;
		$text .= $lin . "\r\n";
	}

	return $text;
}

sub simple {
	my $self = shift;

	my $text;


	foreach my $hdr (@{$self->head}) {
		$hdr->signed or $self->signature->signing or
			next;
		$self->signature->wantheader($hdr->key) or
			next;
		my $line = $hdr->line;
#		print STDERR $line;
		# $line =~ s/([^\r])\n/$1\r\n/g; # yuck
		#$line =~ s/([^\r])\n/$1\r\n/g; # yuck
		#chomp($line);
		$line =~ s/\r?\n/\r\n/gs;
		$text .= $line;
	}

	# delete trailing blank lines
	foreach (reverse @{$self->{'BODY'}}) {
		/[^\r\n]/ and # last non-blank line
			last;
		/^[\r\n]*$/ and
			pop @{$self->{'BODY'}};
	}

	# make sure there is a body before adding a seperator line
	(scalar @{$self->{'BODY'}}) and
		$text .= "\r\n";

	foreach my $lin (@{$self->{'BODY'}}) {
		my $line = $lin;
		#$line eq "\n" and
		#	$line = "\r\n";
		#$line =~ s/([^\r])\n/$1\r\n/g; # yuck
		#$text .= $line;
		$line =~ s/\r?\n/\r\n/gs;
		$text .= $line;
	}

	return $text;
}

sub sign {
	my $self = shift;
	my %prms = @_;

	my $sign = new Mail::DomainKeys::Signature(
		Method => $prms{'Method'},
		Domain => $self->senderdomain,
		Selector => $prms{'Selector'},
		Signing => 1);

	$self->signature($sign);

	$sign->sign(Text => $self->canonify, Private => $prms{'Private'});

	return $sign;
}

sub verify {
	my $self = shift;


	$self->signed or
		return;

	return $self->signature->verify(Text => $self->canonify,
		Sender => ($self->sender or $self->from));

}

sub body {
	my $self = shift;

	(@_) and
		$self->{'BODY'} = shift;

	$self->{'BODY'};
}

sub from {
	my $self = shift;

	(@_) and
		$self->{'FROM'} = shift;

	$self->{'FROM'};
}

sub head {
	my $self = shift;

	(@_) and
		$self->{'HEAD'} = shift;

	$self->{'HEAD'}
}

sub sender {
	my $self = shift;

	(@_) and
		$self->{'SNDR'} = shift;

	$self->{'SNDR'};
}

sub senderdomain {
	my $self = shift;

	$self->sender and
		return $self->sender->host;

	$self->from and
		return $self->from->host;

	return;
}

sub signature {
	my $self = shift;

	(@_) and
		$self->{'SIGN'} = shift;

	$self->{'SIGN'};
}

sub signed {
	my $self = shift;

	$self->signature and
		return 1;

	return;
}

sub testing {
	my $self = shift;

	$self->signed and $self->signature->testing and
		return 1;

	return;
}

1;
