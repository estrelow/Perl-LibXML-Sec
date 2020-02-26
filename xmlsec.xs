#include <xmlsec/xmlsec.h>
#include <xmlsec/xmldsig.h>

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "app.h"
#include "crypto.h"

MODULE = XML::LibXML::xmlsec		PACKAGE = XML::LibXML::xmlsec		

TYPEMAP: <<HERE
xmlSecKeyDataFormat   T_ENUM
HERE

PROTOTYPES: ENABLE

IV 
InitKeyMgr()
   CODE:
      xmlSecKeysMngrPtr pkm = NULL;
      pkm=xmlSecKeysMngrCreate(); 
	  if (pkm == NULL) {
		  croak("xmlSecKeysMngrCreate fail\n");
		  RETVAL=0;
	  } 

	  if (xmlSecCryptoAppDefaultKeysMngrInit(pkm) < 0) {
		  croak("xmlSecCryptoAppDefaultKeysMngrInit fail\n");
		  RETVAL=0;
	  }
       
	  RETVAL=PTR2IV(pkm);
   OUTPUT:
      RETVAL

IV
XmlSecKeyLoad(mngr,file,pass,name,format)
      IV mngr
      char * file
      char * pass
      char * name
      xmlSecKeyDataFormat format
   CODE:
      xmlSecKeysMngrPtr pkm = INT2PTR(xmlSecKeysMngrPtr, mngr);
      RETVAL=xmlSecAppCryptoSimpleKeysMngrKeyAndCertsLoad(pkm,file,pass,name,format);
   OUTPUT:
      RETVAL
