#ifndef _ASN1_OPER_H_
#define _ASN1_OPER_H_


/*------------------------------------------------------------------
*	ASN1_OBJ����Ϊͬ������һ��ASN1�ṹ: ��֤��ṹ��
*
*	+SEQUENCE,Length = 965	---------->ASN1_OBJ
*		+SEQUENCE,Length = 685
*		+SEQUENCE,Length = 3
*		+BIT STRING,Length = 3
*
*------------------------------------------------------------------
*	ASN1_STRING����ΪASN1_OBJ��,ͬ�����ж��ASN1_OBJ: ��֤��ṹ��
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
	unsigned int	headlen;		//�����в��õ�
	unsigned char	header[16];		//�����в��õ�
} ASN1_OBJ;


void DerTime2Str(char *TimeSrc, char * TimeDst);

//-------------------------------OBJ����--------------------------------------

void ASN1_OBJ_init(ASN1_OBJ *pasn1_o);

void ASN1_OBJS_init(ASN1_OBJ *pasn1_o, int count);

void ASN1_OBJ_dump(ASN1_OBJ asn1_o, ASN1_OBJ *pasn1_o);

//-------------------------------Der����--------------------------------------

//	����ASN1_OBJ���͵�TLV����ASN1_OBJ�е�headerͷ
int i2d_ASN1_OBJ(ASN1_OBJ *p_asn1_o);

//	��ASN1_OBJ���͵�����ת��Ϊder��������
int i2d_ASN1_OBJ_set(ASN1_OBJ *p_asn1_o, int count, int merge_tag, unsigned char* der_out, 
	int *p_der_len);

//-------------------------------Der����--------------------------------------

//	��der����ת��ΪASN1_OBJ����(pasn1_o��ͷ�ѽ���)�����ظ�ASN1_OBJ��der_in����ռ��
//	���ܳ���(����ֵ����0Ϊ����)
int d2i_ASN1_OBJ(unsigned char* der_in, int der_len, ASN1_OBJ *p_asn1_o);


//	��der����ת��ΪASN1_OBJ���ͼ���(pasn1_o��ͷ�ѽ���)������der_in��ASN1_OBJ�ܸ���
//	(����ֵ����0Ϊ����)
int d2i_ASN1_OBJ_STRING_obj(unsigned char* der_in, int der_len, ASN1_OBJ *pasn1_o);

//	��der����ת��ΪASN1_OBJ���ͼ���(pasn1_o��ͷδ����)������der_in��ASN1_OBJ�ܸ���
//	(����ֵ����0Ϊ����)
int d2i_ASN1_OBJ_STRING_der(unsigned char* der_in, int der_len, ASN1_OBJ *pasn1_o);


//	��der_in�в��ҵ�appear_times(����0)��TAG == tag��ASN1_OBJ(��ASN1_OBJ�Ѿ�����)��
//	�����ظ�object���der_in��ƫ��(����ֵ����0Ϊ����)
int d2i_ASN1_OBJ_STRING_objsearch(unsigned char* der_in, int der_len, int tag, 
	int appear_times, ASN1_OBJ *pasn1_o);

//	��der_in�в��ҵ�appear_times(����0)��TAG == tag��ASN1_OBJ(��ASN1_OBJ��δ����)��
//	�����ظ�object���der_in��ƫ��(����ֵ����0Ϊ����)
int d2i_ASN1_OBJ_STRING_dersearch(unsigned char* der_in, int der_len, int tag, 
	int appear_times, ASN1_OBJ *pasn1_o);

//-------------------------------X509����--------------------------------------

//	asn1_name����tag��δ����������obj(����ֵ����0Ϊ����)
int X509NameParse(ASN1_OBJ asn1_name, char *pname_str, int name_buf_len);

//	asn1_cert����tag��δ����������obj(����ֵ����0Ϊ����)
int X509CertParse(ASN1_OBJ asn1_cert, char Version[8], char SignAlg[16], char HashAlg[16],
	char *pIssuer, int IssuerBufLen, char *pSubject, int SubjectBufLen, 
	char SN[64], char NotBefore[48],char NotAfter[48], char *pPubKey, int *piPubKeyLen);

//	asn1_cert����tag��δ����������obj(����ֵ����0Ϊ����)
//	����OID��ȡExtension��չ���ж�Ӧ��ֵ
int X509CertGetExt(ASN1_OBJ asn1_cert, char *pExtOid, int *piCritical, char *pValue, int *piValueLen);

//-------------------------------P7B����֤��--------------------------------------

//	����P7B�еĸ���֤�飬������֤�����(����ֵ����0Ϊ����)
int P7BCertParse(unsigned char* der_in, int der_len, ASN1_OBJ *pasn1_o);

//	��p7b�в����û�֤��(����ֵ����0Ϊ����)
int UserCertSearchFromP7b(unsigned char* der_in, int der_len, unsigned char* der_out, int *pout_der_len);

//-------------------------------OIDת��--------------------------------------

//	��OID�ַ���ת��ΪDer����
int Asn1_Oid2Der(char *oidstr, char *der, int *derlen);

//	��Der����ת��ΪOID�ַ���
int Asn1_Der2Oid(char *der, int derlen, char *oidstr);

#endif

