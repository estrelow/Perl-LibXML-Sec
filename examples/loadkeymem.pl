#!/usr/bin/perl
use strict;
use warnings;

use XML::LibXML::xmlsec;

my $signer=XML::LibXML::xmlsec->new();

my $pem= <<'-----END RSA PRIVATE KEY-----';
-----BEGIN RSA PRIVATE KEY-----
MIICxjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQIP1hLLQhDBTQCAggA
MBQGCCqGSIb3DQMHBAhLlOAtzjXM2ASCAoCaG7XsEfbc7sCKAnszGMKdYWQOCL7L
KrpclYyGv3TF1nDr7+mbNhSyUv29JDUTkeVO/j1AGGcQM6JmlEs/0DvtbNAyMBF2
GJ/N55s9eSKpARrD/wmtOXNjjcETYFr82eYL7sOdEaRh0XqHAD1+VwleNCXgLbAE
rM659ULkBZdL7tPo+/u8vBOW6fTSfutnjzP+rZ6yhXzI6yAFzMzspTZiEk4Ppi/p
N0aJ8Q6vwCCAmZ52HSucb7yuR0oIaCUumV8QVTw4hpJzjlaz66TBrC4ro5/fv6s1
obIyHO2PcYqudVQmMNwXdp707UX9qdzxUPAtfVdCHe0YueSy82mlp/BoKtNw9UiT
TlJmFuZd87UM8ZXXIxceYP6jB4Bk68NvdJmSfgdhCR158J/qrQBgbZA4odBVUv8l
D6h5TCYUI+Vd03jE9bBjsWtmtxrRTcMBaVg22Y+TgEG3Z0pVbBzZg4iIA4h3BveE
LWKaAzKPdV/G83aZMdZBK58WSaxH1kllegAs5oErvaR9gmuYSTh53XLpWO5IAisv
iKxSkNwK3CArWstk0bv4JILIxT9y/ic30Whg13dHD9hW1YPmypD9RDrkYntVnUu1
PndFwsjNRi1pv5nAhOeiTpFQZtM/5lEIVWq3Qqr9TzRsfoRqDr+BuFs9y0GqEfes
etwKltcLa8js/wXfDv42Mr7hUtX5DPKWgEeq/jfUYLmfU8S6SWzUoQEmC5MUXEy+
NkypcpiYy3xGNeTtwPMdjLhjUJn+Xv4h7oP+9YQV6B0Ztc/4pbZbjKD+vO6dfEHH
1rj9r1Iy7vruBK0X2YmtNr2mbCQnRmz+Yxq01lCoGfafhQQYg++zv9iT
-----END RSA PRIVATE KEY-----
$signer->loadpkey(PEM => $pem, secret => 'watcher');

