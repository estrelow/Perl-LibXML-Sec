#include <xmlsec/xmlsec.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/openssl/app.h>
#include <xmlsec/xmltree.h>

#include "perl-libxml-mm.h"

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "app.h"
#include "crypto.h"

xmlSecKeyPtr FindKey(xmlSecKeysMngrPtr mngr, xmlChar* name) {
  
   xmlSecKeyPtr r;
   xmlSecKeyInfoCtxPtr ctx=xmlSecKeyInfoCtxCreate(mngr);
   xmlSecKeyInfoCtxInitialize(ctx,mngr);
   r= xmlSecKeysMngrFindKey(mngr, name, ctx);
   xmlSecKeyInfoCtxDestroy(ctx);
   return r;

}

/* extracts the libxml2 node from a perl reference
 */

xmlNodePtr
PmmSvNodeExt( SV* perlnode, int copy )
{
    xmlNodePtr retval = NULL;
    ProxyNodePtr proxy = NULL;
    dTHX;

    if ( perlnode != NULL && perlnode != &PL_sv_undef ) {
/*         if ( sv_derived_from(perlnode, "XML::LibXML::Node") */
/*              && SvPROXYNODE(perlnode) != NULL  ) { */
/*             retval = PmmNODE( SvPROXYNODE(perlnode) ) ; */
/*         } */
        xs_warn("PmmSvNodeExt: perlnode found\n" );
        if ( sv_derived_from(perlnode, "XML::LibXML::Node")  ) {
            proxy = SvPROXYNODE(perlnode);
            if ( proxy != NULL ) {
                xs_warn( "PmmSvNodeExt:   is a xmlNodePtr structure\n" );
                retval = PmmNODE( proxy ) ;
            }

            if ( retval != NULL
                 && ((ProxyNodePtr)retval->_private) != proxy ) {
                xs_warn( "PmmSvNodeExt:   no node in proxy node\n" );
                PmmNODE( proxy ) = NULL;
                retval = NULL;
            }
        }
#ifdef  XML_LIBXML_GDOME_SUPPORT
        else if ( sv_derived_from( perlnode, "XML::GDOME::Node" ) ) {
            GdomeNode* gnode = (GdomeNode*)SvIV((SV*)SvRV( perlnode ));
            if ( gnode == NULL ) {
                warn( "no XML::GDOME data found (datastructure empty)" );
            }
            else {
                retval = gdome_xml_n_get_xmlNode( gnode );
                if ( retval == NULL ) {
                    xs_warn( "PmmSvNodeExt: no XML::LibXML node found in GDOME object\n" );
                }
                else if ( copy == 1 ) {
                    retval = PmmCloneNode( retval, 1 );
                }
            }
        }
#endif
    }

    return retval;
}


/**
 * xmlSecGetNextElementNode:
 * @cur:                the pointer to an XML node.
 *
 * Seraches for the next element node.
 *
 * Returns: the pointer to next element node or NULL if it is not found.
 */
xmlNodePtr
xmlSecGetNextElementNode(xmlNodePtr cur) {

    while((cur != NULL) && (cur->type != XML_ELEMENT_NODE)) {
        cur = cur->next;
    }
    return(cur);
}

static int  
xmlSecAppAddIDAttr(xmlNodePtr node, const xmlChar* attrName, const xmlChar* nodeName, const xmlChar* nsHref) {
    xmlAttrPtr attr, tmpAttr;
    xmlNodePtr cur;
    xmlChar* id;
    
    if((node == NULL) || (attrName == NULL) || (nodeName == NULL)) {
        return(-1);
    }
    
    /* process children first because it does not matter much but does simplify code */
    cur = xmlSecGetNextElementNode(node->children);
    while(cur != NULL) {
        if(xmlSecAppAddIDAttr(cur, attrName, nodeName, nsHref) < 0) {
            return(-1);
        }
        cur = xmlSecGetNextElementNode(cur->next);
    }
    
    /* node name must match */
    if(!xmlStrEqual(node->name, nodeName)) {
        return(0);
    }
        
    /* if nsHref is set then it also should match */    
    if((nsHref != NULL) && (node->ns != NULL) && (!xmlStrEqual(nsHref, node->ns->href))) {
        return(0);
    }
    
    /* the attribute with name equal to attrName should exist */
    for(attr = node->properties; attr != NULL; attr = attr->next) {
        if(xmlStrEqual(attr->name, attrName)) {
            break;
        }
    }
    if(attr == NULL) {
        return(0);
    }
    
    /* and this attr should have a value */
    id = xmlNodeListGetString(node->doc, attr->children, 1);
    if(id == NULL) {
        return(0);
    }
    
    /* check that we don't have same ID already */
    tmpAttr = xmlGetID(node->doc, id);
    if(tmpAttr == NULL) {
        xmlAddID(NULL, node->doc, id, attr);
    } else if(tmpAttr != attr) {
        fprintf(stderr, "Error: duplicate ID attribute \"%s\"\n", id);  
        xmlFree(id);
        return(-1);
    }
    xmlFree(id);
    return(0);
}

MODULE = XML::LibXML::xmlsec		PACKAGE = XML::LibXML::xmlsec		

TYPEMAP: <<HERE
xmlSecKeyDataFormat   T_ENUM
xmlChar *             T_PV
HERE

PROTOTYPES: ENABLE

BOOT:
   // No libxml initialization here. XML::LibXML should handle that
   LIBXML_TEST_VERSION

   int ret=xmlSecInit();
   if(ret < 0) {
        croak("Error: xmlsec intialization failed");
   }
   ret=xmlSecCryptoAppInit(NULL);
   if(ret < 0) {
        croak("Error: xmlsec crypto app engine intialization failed");
   }
   ret=xmlSecCryptoInit();
   if(ret < 0) {
        croak("Error: xmlsec crypto engine intialization failed");
   }


int
InitPerlXmlSec(self)
      SV * self
   CODE:
/********************************************************************
   InitPerlXmlSec()

   Placeholder for general xmlsec initialization
*********************************************************************/
   // No libxml initialization here. XML::LibXML should handle that
      int ret=0;
	  ret = xmlSecCheckVersion();
	  if (ret != 1) {
        croak("Error: xmlsec version mismatch.\n");
        ret=0;
	  }

	  RETVAL=ret;

   OUTPUT:
      RETVAL


IV 
InitKeyMgr(self)
      SV * self
   CODE:
/********************************************************************
   InitPerlXmlSec()

   Setup the main KeyMgr object. This is needed for further method
   calls
*********************************************************************/
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
      xmlChar * file
      xmlChar * pass
      xmlChar * name
      xmlSecKeyDataFormat format
   CODE:
/********************************************************************
   XmlSecKeyLoad()

   Loads a key from a file into the keymanager. This mainly maps
   to xmlsec's xmlSecCryptoAppDefaultKeysMngrAdoptKey()
		 Args:
		    self
			mngr: the key manager attached to us
			file: the external file name
			pass: the password for key decryption
			name: an optional name
         Return value:
		    whatever xmlSecCryptoAppDefaultKeysMngrAdoptKey
*********************************************************************/
      xmlSecKeysMngrPtr pkm = INT2PTR(xmlSecKeysMngrPtr, mngr);
	  xmlSecKeyPtr key;
      int ret=0;

      key = xmlSecCryptoAppKeyLoad(file, format, pass, 
                xmlSecCryptoAppGetDefaultPwdCallback(), (void*)file);
      if (key == NULL)
      {
		  croak ("xmlSecCryptoAppKeyLoad fail");
      }
      
	  ret = xmlSecKeySetName(key,  name);
	  ret = xmlSecCryptoAppDefaultKeysMngrAdoptKey(pkm, key);
	  if (ret < 0) {
		  croak ("xmlSecCryptoAppDefaultKeysMngrAdoptKey fail");
	  }
	  RETVAL=ret;
   OUTPUT:
      RETVAL

IV
xmlSecKeyLoadString(self,mngr,data,pass,name,format)
      SV * self
      IV mngr
      xmlChar * data
      xmlChar * pass
      xmlChar * name
      xmlSecKeyDataFormat format
   CODE:
/********************************************************************
   xmlSecKeyLoadString()

   This is the in-memory version of XmlSecKeyLoad()
*********************************************************************/
      xmlSecKeysMngrPtr pkm = INT2PTR(xmlSecKeysMngrPtr, mngr);
	  xmlSecKeyPtr key;
      xmlSecSize s = strlen(data);
	  int ret;

      key=xmlSecCryptoAppKeyLoadMemory (data,s,format,pass,xmlSecCryptoAppGetDefaultPwdCallback(), NULL);

      if (key == NULL)
      {
		  die ("xmlSecCryptoAppKeyLoad fail");
      }
      ret = xmlSecKeySetName(key,  name);
	  ret = xmlSecCryptoAppDefaultKeysMngrAdoptKey(pkm, key);
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
/********************************************************************
   XmlSecVersion()

   Returns the underlying xmlsec version. Please note that this is 
   a static call based on a cpp macro. xmlsec doesn't provide a 
   dynamic link to the version, only cleverly setup MACROS and a 
   xmlSecCheckVersion function call
*********************************************************************/
      RETVAL = XMLSEC_VERSION;
   OUTPUT:
      RETVAL

int
XmlSecSignDoc(self,doc,mgr, id_attr, id_name, id)
   HV * self;        
   SV * doc;         //The already setup libxml Document
   IV mgr;           //The IV packed key manager ptr
   xmlChar * id_attr;//The name of the attribute used as id
   xmlChar * id_name;//The tagname of the targetted node
   xmlChar * id;     //The id value of the targetted node
  CODE:
/********************************************************************
   XmlSecSignDoc()

   Entry point for signing process
*********************************************************************/
   int ret=0;
   xmlDocPtr real_doc;
   xmlChar* buf;
   xmlChar* nodeName;
   xmlChar* nsHref;
   xmlAttrPtr attr;
   xmlNodePtr cur;
   xmlNodePtr startNode;

   if (id_attr == NULL) {
	   die( "id-attr must be specified");
   }

   if (id == NULL) {
	   die( "id must be specified");
   }

   SV ** pm= hv_fetch(self,"_keymgr",7,0);
   if (pm == NULL)
   {
      die ("Key Manager missing can't sign");
   }
   xmlSecKeysMngrPtr pkm=INT2PTR(xmlSecKeysMngrPtr, mgr);
   
   xmlSecDSigCtx dsigCtx;

   ret=xmlSecDSigCtxInitialize(&dsigCtx, pkm);
   if (ret < 0)   {
	   die("Error xmlSecDSigCtxInitialize fail");
   }


   real_doc=(xmlDocPtr) PmmSvNode(doc);
   if (real_doc == NULL)  {
	   die("Error: failed to get libxml doc");
   }

   /* set id atribute */
   buf = xmlStrdup(id_name);
   nodeName = (xmlChar*)strrchr((char*)buf, ':');
   if(nodeName != NULL) {
	   (*(nodeName++)) = '\0';
	   nsHref = buf;
	} else {
	   nodeName = buf;
	   nsHref = NULL;
	}

    cur = xmlSecGetNextElementNode(real_doc->children);
	while(cur != NULL) {
		if(xmlSecAppAddIDAttr(cur, id_attr, nodeName, nsHref) < 0) {
			xmlFree(buf);
			die ("Error: xmlSecAppAddIDAttr failed");
		}
		cur = xmlSecGetNextElementNode(cur->next);
	}
    xmlFree(buf);

    /* find starting node by id */
    attr = xmlGetID(real_doc, id);
	if (attr == NULL)	{
		die("Error: xmlsec fail to find starting node");
	}
	
	startNode = xmlSecFindNode(attr->parent, "Signature", "http://www.w3.org/2000/09/xmldsig#");
	if (startNode == NULL)
	{
		die( "Error: xmlsec fail to find Signature node");
	}
	ret=xmlSecDSigCtxSign(&dsigCtx, startNode);
	if (ret < 0)
	{
		die("Error xmlsec signature failed");
	}

    xmlSecDSigCtxFinalize(&dsigCtx);

	RETVAL=ret;

  OUTPUT:
   RETVAL

int
KeyCertLoad(self,mgr,name,secret,file,format) 
   SV * self;    
   IV mgr;          //The key manager ptr, IV packed
   xmlChar * name;  //the keyname bound to the certificate
   xmlChar * secret;//The password for decrypting the certificate
   xmlChar * file;  //Certificate filename
   xmlSecKeyDataFormat format; //The format of the certificate file
CODE:
/********************************************************************
   KeyCertLoad()

   Entry point for x509 certificate loading
*********************************************************************/

   int ret=0;
   xmlSecKeysMngrPtr pkm=INT2PTR(xmlSecKeysMngrPtr, mgr);
   xmlSecKeyPtr key=FindKey(pkm,name);
   if (key==NULL)  { /* There's no key yet */
      key=xmlSecCryptoAppKeyLoad (file,format,secret,xmlSecCryptoAppGetDefaultPwdCallback(),file);
      //printf ("Loaded cert as new key\n");
	  if (key == NULL) {
		  die ("Can't load certificate file");
	  }
      ret = xmlSecKeySetName(key,  name);
	  ret = xmlSecCryptoAppDefaultKeysMngrAdoptKey(pkm, key);
      
   } else { /* we attach the certificate to the previously loaded key */
      ret=xmlSecCryptoAppKeyCertLoad (key,file,xmlSecKeyDataFormatPem);
      //printf ("Loaded cert as attribute\n");
	  if (ret<0) {
		  die("Can't load certificate file");
	  }

   }

   RETVAL=ret;
  OUTPUT:
   RETVAL

int
_KeysStoreSave (self, mgr,filename,type)
   SV * self;
   IV mgr;
   char * filename;
   int type;
CODE:
/********************************************************************
   _KeysStoreSave()

   Dumps the contents of the key manager for further use
   This maps to xmlSecCryptoAppDefaultKeysMngrSave()
*********************************************************************/
   xmlSecKeysMngrPtr pkm=INT2PTR(xmlSecKeysMngrPtr, mgr);
   RETVAL=xmlSecCryptoAppDefaultKeysMngrSave  (pkm,filename,type);
OUTPUT:
   RETVAL

int
_KeysStoreLoad (self, mgr,filename)
   SV * self;
   IV mgr;
   char * filename;
CODE:
/********************************************************************
   _KeysStoreSave()

   Dumps the contents of the key manager for further use
   This maps to xmlSecCryptoAppDefaultKeysMngrLoad()
*********************************************************************/
   xmlSecKeysMngrPtr pkm=INT2PTR(xmlSecKeysMngrPtr, mgr);
   RETVAL=xmlSecCryptoAppDefaultKeysMngrLoad   (pkm,filename);
OUTPUT:
   RETVAL


