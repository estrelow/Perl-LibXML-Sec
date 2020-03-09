use 5.016003;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'XML::LibXML::xmlsec',
    VERSION_FROM      => 'lib/XML/LibXML/xmlsec.pm', # finds $VERSION
    PREREQ_PM         => {'XML::LibXML'}, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/XML/LibXML/xmlsec.pm', # retrieve abstract from module
       AUTHOR         => 'Erich Strelow <esf@moller.cl>') : ()),
    LIBS              => ['-L/usr/local/lib -lxmlsec1-openssl -lxmlsec1 -lltdl  -lxml2    -lssl -lcrypto'], 
    DEFINE            => '-DXMLSEC_NO_CRYPTO_DYNAMIC_LOADING -D__XMLSEC_FUNCTION__=__func__ -DXMLSEC_NO_SIZE_T -DXMLSEC_NO_XSLT=1 -DXMLSEC_NO_GOST=1 -DXMLSEC_NO_GOST2012=1 -DXMLSEC_DL_LIBLTDL=1 -DXMLSEC_CRYPTO_OPENSSL=1',
    INC               => '-I. -I/usr/include/libxml2 -I/usr/include/xmlsec1', 
    OBJECT            => 'xmlsec.o crypto.o', # link all the C files too
);
