#ifndef _ASN1_OPER_H_
#define _ASN1_OPER_H_


/*------------------------------------------------------------------
*	ASN1_OBJ定义为同级仅有一个ASN1结构: 如证书结构：
*
*	+SEQUENCE,Length = 965	---------->ASN1_OBJ
*		+SEQUENCE,Length = 685
*		+SEQUENCE,Length = 3
*		+BIT STRING,Length = 3
*
*------------------------------------------------------------------
*	ASN1_STRING定义为ASN1_OBJ串,同级含有多个ASN1_OBJ: 如证书结构：
*
*	+SEQUENCE,Length = 685		-|
*	+SEQUENCE,Length = 3		 |---------------->ASN1_STRING
*	+BIT STRING,Length = 3		-|
*
*------------------------------------------------------------------*/


#define V_ASN1_NEG				0x100	/* negative flag */
#define V_ASN1_BOOLEAN			1
#define V_ASN1_INTEGER			2
#define V_ASN1_NEG_INTEGER		(2 | V_ASN1_NEG)
#define V_ASN1_BIT_STRING		3
#define V_ASN1_OCTET_STRING		4
#define V_ASN1_NULL				5
#define V_ASN1_OBJECT			6
#define V_ASN1_OBJECT_DESCRIPTOR	7
#define V_ASN1_EXTERNAL			8
#define V_ASN1_REAL				9
#define V_ASN1_ENUMERATED		10
#define V_ASN1_NEG_ENUMERATED	(10 | V_ASN1_NEG)
#define V_ASN1_UTF8STRING		12
#define V_ASN1_SEQUENCE			16
#define V_ASN1_SET				17
#define V_ASN1_NUMERICSTRING	18
#define V_ASN1_PRINTABLESTRING	19
#define V_ASN1_T61STRING		20
#define V_ASN1_TELETEXSTRING	20	/* alias */
#define V_ASN1_VIDEOTEXSTRING	21
#define V_ASN1_IA5STRING		22
#define V_ASN1_UTCTIME			23
#define V_ASN1_GENERALIZEDTIME	24
#define V_ASN1_GRAPHICSTRING	25
#define V_ASN1_ISO64STRING		26
#define V_ASN1_VISIBLESTRING	26	/* alias */
#define V_ASN1_GENERALSTRING	27
#define V_ASN1_UNIVERSALSTRING	28
#define V_ASN1_BMPSTRING		30

#define V_ASN1_ASN1_80          0x80
#define V_ASN1_ASN1_86          0x86
#define V_ASN1_ASN1_A0          0xA0
#define V_ASN1_ASN1_A1          0xA1
#define V_ASN1_ASN1_A2          0xA2
#define V_ASN1_ASN1_A3          0xA3
#define V_ASN1_ASN1_A4          0xA4


typedef struct 
{
	unsigned int	tag;
	unsigned int	len;
	unsigned char*	value;
	unsigned int	headlen;		//编码中才用到
	unsigned char	header[16];		//编码中才用到
} ASN1_OBJ;


void DerTime2Str(char *TimeSrc, char * TimeDst);

//-------------------------------OBJ操作--------------------------------------

void ASN1_OBJ_init(ASN1_OBJ *pasn1_o);

void ASN1_OBJS_init(ASN1_OBJ *pasn1_o, int count);

void ASN1_OBJ_dump(ASN1_OBJ asn1_o, ASN1_OBJ *pasn1_o);

//-------------------------------Der编码--------------------------------------

//	根据ASN1_OBJ类型的TLV构造ASN1_OBJ中的header头
int i2d_ASN1_OBJ(ASN1_OBJ *p_asn1_o);

//	将ASN1_OBJ类型的数组转换为der编码数据
int i2d_ASN1_OBJ_set(ASN1_OBJ *p_asn1_o, int count, int merge_tag, unsigned char* der_out, 
	int *p_der_len);

//-------------------------------Der解码--------------------------------------

//	由der编码转换为ASN1_OBJ类型(pasn1_o的头已解析)，返回该ASN1_OBJ在der_in中所占用
//	的总长度(返回值大于0为正常)
int d2i_ASN1_OBJ(unsigned char* der_in, int der_len, ASN1_OBJ *p_asn1_o);


//	由der编码转换为ASN1_OBJ类型集合(pasn1_o的头已解析)，返回der_in中ASN1_OBJ总个数
//	(返回值大于0为正常)
int d2i_ASN1_OBJ_STRING_obj(unsigned char* der_in, int der_len, ASN1_OBJ *pasn1_o);

//	由der编码转换为ASN1_OBJ类型集合(pasn1_o的头未解析)，返回der_in中ASN1_OBJ总个数
//	(返回值大于0为正常)
int d2i_ASN1_OBJ_STRING_der(unsigned char* der_in, int der_len, ASN1_OBJ *pasn1_o);


//	在der_in中查找第appear_times(大于0)个TAG == tag的ASN1_OBJ(该ASN1_OBJ已经解析)，
//	并返回该object相对der_in的偏移(返回值大于0为正常)
int d2i_ASN1_OBJ_STRING_objsearch(unsigned char* der_in, int der_len, int tag, 
	int appear_times, ASN1_OBJ *pasn1_o);

//	在der_in中查找第appear_times(大于0)个TAG == tag的ASN1_OBJ(该ASN1_OBJ并未解析)，
//	并返回该object相对der_in的偏移(返回值大于0为正常)
int d2i_ASN1_OBJ_STRING_dersearch(unsigned char* der_in, int der_len, int tag, 
	int appear_times, ASN1_OBJ *pasn1_o);

//-------------------------------X509解码--------------------------------------

//	asn1_name不含tag是未经过解析的obj(返回值等于0为正常)
int X509NameParse(ASN1_OBJ asn1_name, char *pname_str, int name_buf_len);

//	asn1_cert不含tag是未经过解析的obj(返回值等于0为正常)
int X509CertParse(ASN1_OBJ asn1_cert, char Version[8], char SignAlg[16], char HashAlg[16],
	char *pIssuer, int IssuerBufLen, char *pSubject, int SubjectBufLen, 
	char SN[64], char NotBefore[48],char NotAfter[48], char *pPubKey, int *piPubKeyLen);

//	asn1_cert不含tag是未经过解析的obj(返回值等于0为正常)
//	根据OID获取Extension扩展项中对应的值
int X509CertGetExt(ASN1_OBJ asn1_cert, char *pExtOid, int *piCritical, char *pValue, int *piValueLen);

//-------------------------------P7B解析证书--------------------------------------

//	解析P7B中的各个证书，并返回证书个数(返回值大于0为正常)
int P7BCertParse(unsigned char* der_in, int der_len, ASN1_OBJ *pasn1_o);

//	从p7b中查找用户证书(返回值等于0为正常)
int UserCertSearchFromP7b(unsigned char* der_in, int der_len, unsigned char* der_out, int *pout_der_len);

//-------------------------------OID转换--------------------------------------

//	将OID字符串转换为Der编码
int Asn1_Oid2Der(char *oidstr, char *der, int *derlen);

//	将Der编码转换为OID字符串
int Asn1_Der2Oid(char *der, int derlen, char *oidstr);

#endif

