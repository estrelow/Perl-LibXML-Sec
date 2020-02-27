package XML::LibXML::xmlsec;

use 5.016003;
use strict;
use warnings;
use Carp;

require Exporter;
use AutoLoader;

use XML::LibXML;

use enum qw( xmlSecKeyDataFormatUnknown=0
    xmlSecKeyDataFormatBinary
    xmlSecKeyDataFormatPem
    xmlSecKeyDataFormatDer
    xmlSecKeyDataFormatPkcs8Pem
    xmlSecKeyDataFormatPkcs8Der
    xmlSecKeyDataFormatPkcs12
    xmlSecKeyDataFormatCertPem
    xmlSecKeyDataFormatCertDer
);

our @ISA = qw(Exporter);

our $VERSION = '0.01';



require XSLoader;
XSLoader::load('XML::LibXML::xmlsec', $VERSION);


sub new() {
   my $class=shift();
   my $self= bless {}, $class;
   my $ret=$self->InitPerlXmlSec();
   die "Can't initializa xmlsec engine $ret" unless ($ret);

   my $km=$self->InitKeyMgr();
   die "Can't initialize xmlsec KeyManager" unless ($km);
   $self->{_keymgr}=$km;

   return $self;
}

sub set_pkey() {

   my $self=shift();
   my %options=@_;

   my $secret='';
   my $name='';
   my $file;

   $secret=$options{secret} if (exists $options{secret});
   $name=$options{name} if (exists $options{name});

   if (exists $options{PEM}) {
      $file=$options{PEM};
      die "Can't access PEM file $file" unless (-r $file);
      return $self->XmlSecKeyLoad($self->{_keymgr},$file,$secret,$name,xmlSecKeyDataFormatPem);
   }

   if (exists $options{DER}) {
      $file=$options{DER};
      die "Can't access DER file $file" unless (-r $file);
      return $self->XmlSecKeyLoad($self->{_keymgr},$file,$secret,$name,xmlSecKeyDataFormatDer);
   }

}


1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

XML::LibXML::xmlsec - Perl bindings for xmlsec library

=head1 SYNOPSIS

  use XML::LibXML::xmlsec;
  
 


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
