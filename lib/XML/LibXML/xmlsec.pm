package XML::LibXML::xmlsec;

use 5.016003;
use strict;
use warnings;
use Carp;

require Exporter;
use AutoLoader;

use XML::LibXML;
use Scalar::Util qw(blessed);

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

sub loadpkey() {

   my $self=shift();
   my %options=@_;

   my $secret='';
   my $name='';
   my $file;
   my $ret;

   $secret=$options{secret} if (exists $options{secret});

   if (exists $options{name}) {
      $name=$options{name};
   } else {
      $name= 'noname';
   }

   if (exists $options{PEM}) {
      $file=$options{PEM};
      croak "Can't access PEM file $file" unless (-r $file);
      $name=$file unless ($name);
      $ret= $self->XmlSecKeyLoad($self->{_keymgr},$file,$secret,$name,xmlSecKeyDataFormatPem);
   }

   if (exists $options{DER}) {
      $file=$options{DER};
      $name=$file unless ($name);
      croak "Can't access DER file $file" unless (-r $file);
      $ret= $self->XmlSecKeyLoad($self->{_keymgr},$file,$secret,$name,xmlSecKeyDataFormatDer);
   }

   my $pfx;

   # PKCS12, PFX, P12 are equivalent
   $pfx= $options{PKCS12} if (exists $options{PKCS12});
   $pfx= $options{PFX} if (exists $options{PFX});
   $pfx= $options{P12} if (exists $options{P12});

   if ($pfx) {
      $name=$pfx unless ($name);
      croak "Can't access PKCS12 file $pfx" unless (-r $pfx);
      $ret= $self->XmlSecKeyLoad($self->{_keymgr},$file,$secret,$name,xmlSecKeyDataFormatPkcs12);
   }

   return $ret;

}

sub loadcert() {
   
   my $self=shift();
   my %options=@_;

   my $name;

   if (exists $options{name}) {
      $name=$options{name};
   } else {
      $name= 'noname';
   }

   my $file;
   my $format;
   if (exists $options{PEM}) {
      $file=$options{PEM};
      $format=xmlSecKeyDataFormatCertPem;
   }

   if (exists $options{DER}) {
      $file=$options{DER};
      $format=xmlSecKeyDataFormatCertDer;
   }

   my $secret=0;
   $secret= $options{secret} if (exists $options{secret});
   return $self->KeyCertLoad($self->{_keymgr},$name,$secret,$file,$format);
}

sub signdoc() {

   my $self=shift();
   my $doc=shift();
   my %options=@_;

   my $id;
   my $id_attr='id';
   my $id_node;

   $id=$options{'id'} if (exists $options{id});
   $id_attr=$options{'id-attr'} if (exists $options{'id-attr'});
   $id_node=$options{'id-node'} if (exists $options{'id-node'});

   unless ($id_node) {
      $id_node=$doc->documentElement->nodeName;
   }

   my $r=$self->XmlSecSignDoc($doc,$self->{_keymgr},$id_attr,$id_node,$id);

   return $doc;
}

1;
__END__

=head1 NAME

XML::LibXML::xmlsec - XML signing/encription using xmlsec library

=head1 SYNOPSIS

  use XML::LibXML::xmlsec;
  
  my $signer=XML::LibxXML::xmlsec->new();
  $signer->loadpkey(PEM => 'jdoe.pem', secret => 'hush');
  $signer->signdoc($xmldoc);

=head1 DESCRIPTION

XML::LibXML::xmlsec is a bind module for xmlsec, a C library aimed for XML digital signature and encryption
es described in W3C standards.


=head2 INSTALLATION

You must have a running xmlsec library. There are binaries been ported to many Linux distributions, as
well as binaries for Windows available.


=head1 METHODS

=head2 loadpkey

   $signer->loadpkey(PEM => 'me.pem', secret => 'mypassword');
   $signer->loadpkey(DER => 'me.pem', name => 'joe');
   $signer->loadpkey(PEM => $string_with_pem);

loadpkey will set the private key needed for digital signature. The key may be passed as a filename
value, or it might be the key itself. A PEM=>val pair indicates PEM format, DER=>val indicates DER format
and PFX=>val indicates PKCS12 format.
An optional secret value will be used to decrypt the key. 
An optional name argument will be used to mention the private key in further methods.

=head2 loadcert

   $signer->loadcert(PEM => 'me.crt', secret => 'hush')
   $signer->loadcert(PEM => 'joe.crt', name => 'joe')

loadcert will set the X509 certificate needed for verifying or digital signature. The value may be passed
in similar fashion as in loadpkey().

=head2 signdoc

   $signer->signdoc($xmldoc);

signdoc will compute the digital signature and then add it as contents to the XML document.
The argument is expected to be a well behaved L<LibXML::Document|https://metacpan.org/pod/distribution/XML-LibXML/lib/XML/LibXML/Document.pod>



=head1 SEE ALSO

See L<W3C XML signature definition|https://www.w3.org/TR/xmldsig-core/>.
See L<W3C XML encryption definition|https://www.w3.org/TR/xmlenc-core/>.
The original xmlsec library has a webpage at L<https://www.aleksey.com/xmlsec/>

=head1 AUTHOR

Erich Strelow, E<lt>hstrelo@puc.clE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2020 by A. U. Thor

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.16.3 or,
at your option, any later version of Perl 5 you may have available.


=cut
