#!/usr/bin/perl
use strict;
use warnings;

use XML::LibXML::xmlsec;

my $signer=XML::LibXML::xmlsec->new();

$signer->set_pkey(PEM => 'key.pem', secret => 'the watcher and the tower');

my $doc=XML::LibXML->load_xml(location => 'hello-ready.xml', load_ext_dtd =>1, complete_attributes=>1,no_network=>1);
print $doc->toString(1);

$signer->signdoc($doc, id => "hello", 'id-node' => 'Data', 'id-attr' => 'id');
#$signer->signdoc($doc, id => "hello");
print $doc->toString(1);
