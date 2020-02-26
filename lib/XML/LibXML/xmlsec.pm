package XML::LibXML::xmlsec;

use 5.016003;
use strict;
use warnings;
use Carp;

require Exporter;
use AutoLoader;

use XML::LibXML;

our @ISA = qw(Exporter);

our $VERSION = '0.01';

sub AUTOLOAD {
    # This AUTOLOAD is used to 'autoload' constants from the constant()
    # XS function.

    my $constname;
    our $AUTOLOAD;
    ($constname = $AUTOLOAD) =~ s/.*:://;
    croak "&XML::LibXML::xmlsec::constant not defined" if $constname eq 'constant';
    my ($error, $val) = constant($constname);
    if ($error) { croak $error; }
    {
	no strict 'refs';
	# Fixed between 5.005_53 and 5.005_61
#XXX	if ($] >= 5.00561) {
#XXX	    *$AUTOLOAD = sub () { $val };
#XXX	}
#XXX	else {
	    *$AUTOLOAD = sub { $val };
#XXX	}
    }
    goto &$AUTOLOAD;
}

require XSLoader;
XSLoader::load('XML::LibXML::xmlsec', $VERSION);

# Preloaded methods go here.

# Autoload methods go after =cut, and are processed by the autosplit program.


sub new() {
   my $class=shift();
   my $self= bless {}, $class;
   $self->{_keymgr}=InitKeyMgr;
   return $self;
}

sub set_pkey() {

   my $self=shift();
   my %options=@_;

   my $secret='';

   $secret=$options{secret} if (exists $options{secret});

}


1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

XML::LibXML::xmlsec - Perl extension for blah blah blah

=head1 SYNOPSIS

  use XML::LibXML::xmlsec;
  blah blah blah

=head1 DESCRIPTION

Stub documentation for XML::LibXML::xmlsec, created by h2xs. It looks like the
author of the extension was negligent enough to leave the stub
unedited.

Blah blah blah.

=head2 EXPORT

None by default.

=head2 Exportable constants

  xmlSecByte
  xmlSecCheckVersionABICompatible
  xmlSecCheckVersionExactMatch
  xmlSecSize



=head1 SEE ALSO

Mention other useful documentation such as the documentation of
related modules or operating system documentation (such as man pages
in UNIX), or any relevant external documentation such as RFCs or
standards.

If you have a mailing list set up for your module, mention it here.

If you have a web site set up for your module, mention it here.

=head1 AUTHOR

A. U. Thor, E<lt>estrelow@localdomainE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2020 by A. U. Thor

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.16.3 or,
at your option, any later version of Perl 5 you may have available.


=cut
