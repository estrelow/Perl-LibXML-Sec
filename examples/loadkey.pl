#!/usr/bin/perl
use strict;
use warnings;

use XML::LibXML::xmlsec;

my $signer=XML::LibXML::xmlsec->new();

$signer->set_pkey(PEM => 'key.pem', secret => 'the watcher and the tower');

