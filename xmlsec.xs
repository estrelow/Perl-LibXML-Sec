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

BOOT:
   # No libxml initialization here. XML::LibXML should handle that
   LIBXML_TEST_VERSION

   int ret=xmlSecInit();
   if(ret < 0) {
        die("Error: xmlsec intialization failed");
   }
   ret=xmlSecCryptoAppInit(NULL);
   if(ret < 0) {
        die("Error: xmlsec crypto app engine intialization failed");
   }
   ret=xmlSecCryptoInit();
   if(ret < 0) {
        die("Error: xmlsec crypto engine intialization failed");
   }



int
InitPerlXmlSec(self)
      SV * self
   CODE:
   # No libxml initialization here. XML::LibXML should handle that
      int ret=0;
	  ret = xmlSecCheckVersion();
	  if (ret != 1) {
        warn("Error: xmlsec version mismatch.\n");
        ret=0;
	  }

	  RETVAL=ret;

   OUTPUT:
      RETVAL


IV 
InitKeyMgr(self)
      SV * self
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
XmlSecKeyLoad(self,mngr,file,pass,name,format)
      SV * self
      IV mngr
      char * file
      char * pass
      char * name
      xmlSecKeyDataFormat format
   CODE:
      xmlSecKeysMngrPtr pkm = INT2PTR(xmlSecKeysMngrPtr, mngr);
	  xmlSecKeyPtr key;

      key = xmlSecCryptoAppKeyLoad(file, format, pass, 
                xmlSecCryptoAppGetDefaultPwdCallback(), (void*)file);
      if (key == NULL)
      {
		  die ("xmlSecCryptoAppKeyLoad fail");
      }

	  int ret = xmlSecCryptoAppDefaultKeysMngrAdoptKey(pkm, key);
	  if (ret < 0) {
		  die ("xmlSecCryptoAppDefaultKeysMngrAdoptKey fail");
	  }
	  RETVAL=ret;
   OUTPUT:
      RETVAL

IV
xmlSecKeyLoadString(self,mngr,data,pass,name,format)
      SV * self
      IV mngr
      char * data
      char * pass
      char * name
      xmlSecKeyDataFormat format
   CODE:
      xmlSecKeysMngrPtr pkm = INT2PTR(xmlSecKeysMngrPtr, mngr);
	  xmlSecKeyPtr key;
      xmlSecSize s = strlen(data);
      key=xmlSecCryptoAppKeyLoadMemory (data,s,format,pass,xmlSecCryptoAppGetDefaultPwdCallback(), NULL);

      if (key == NULL)
      {
		  die ("xmlSecCryptoAppKeyLoad fail");
      }

	  int ret = xmlSecCryptoAppDefaultKeysMngrAdoptKey(pkm, key);
	  if (ret < 0) {
		  die ("xmlSecCryptoAppDefaultKeysMngrAdoptKey fail");
	  }
	  RETVAL=ret;

   OUTPUT:
      RETVAL


char *
XmlSecVersion(self)
      SV * self
   CODE:
      RETVAL = XMLSEC_VERSION;
   OUTPUT:
      RETVAL
