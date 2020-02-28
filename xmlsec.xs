#include <xmlsec/xmlsec.h>
#include <xmlsec/xmldsig.h>
#include "perl-libxml-mm.h"

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "app.h"
#include "crypto.h"

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

int
XmlSecSignDoc(self,doc, id_attr, id_name, id)
   HV * self
   SV * doc
   xmlChar * id_attr;
   xmlChar * id_name;
   xmlChar * id;
  CODE:
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
   xmlSecKeysMngrPtr pkm=(xmlSecKeysMngrPtr) *pm;
   
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

	printf("Settind id attr %s for %s nodes\n",id_attr, nodeName);
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
	
	printf("Found starting node\n");
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
