#!/usr/bin/perl
use strict;
use warnings;

use XML::LibXML::xmlsec;

my $signer=XML::LibXML::xmlsec->new();

$signer->loadpkey(PEM => 'key.pem', secret => 'the watcher and the tower');
$signer->loadcert(PEM => 'esf.pem');

my $doc=XML::LibXML->load_xml(location => 'hello-ready.xml');

$signer->KeysStoreSave('keystore.xml',XML::LibXML::xmlsec::xmlSecKeyDataTypeAny);
