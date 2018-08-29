#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include "Asn1Oper.h"


unsigned char item_CN[] = {0x55, 0x04, 0x03};
unsigned char item_C[] = {0x55, 0x04, 0x06};
unsigned char item_O[] = {0x55, 0x04, 0x0A};
unsigned char item_OU[] = {0x55, 0x04, 0x0B};
unsigned char item_L[] = {0x55, 0x04, 0x07};
unsigned char item_S[] = {0x55, 0x04, 0x08};
unsigned char item_E[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01};

char bSM3SM2[] = {0x2A, 0x81,0x1C,0xCF,0x55,0x01,0x83,0x75};
char bSHA1SM2[] = {0x2A, 0x81,0x1C,0x81,0x45,0x01,0x83,0x76};
char bSHA256SM2[] = {0x2A, 0x81,0x1C,0x81,0x45,0x01,0x83,0x77};

char bMD2RSA[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x02};
char bMD4RSA[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x03};
char bMD5RSA[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x04};
char bSHA1RSA[]= {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05};
char bSHA256RSA[]={0x2A,0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B};
char bSHA384RSA[]={0x2A,0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C};
char bSHA512RSA[]={0x2A,0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D};




//	判断主机字节序
int TestByteOrder()
{
	int i = 0x12345678;  
	if(*((char*)&i) == 0x12)	//Aix
		return 1;  //Aix
	else  
		return 0;  //Linux Windows
}

//	将序列号有十六进制数组转换为字符串
void SprintSN(char * Deststr,unsigned char * str,int len)
{
	int i=0;
	for(i=0;i<len;i++)
	{
		sprintf(Deststr+i*2,"%02X",str[i]);
	}
}

int MemCmp(unsigned char * mem1, char * mem2, int mem1len, int mem2len)
{
	if (mem1len != mem2len)
		return -1;

	return memcmp(mem1, mem2, mem1len);
}



//	将从证书编码中直接获取的时间（150122023407）改为形如“2015-01-22 10:34:07”
//	的本地时间字符串
void DerTime2Str(char *TimeSrc, char * TimeDst)
{
	struct tm time;

	struct tm *ptr;

	char Tmp[8] = {0x00};
	time_t timep;

	memcpy(Tmp, TimeSrc, 2);	
	time.tm_year = 100 + atoi(Tmp);

	memcpy(Tmp, TimeSrc + 2, 2);
	time.tm_mon =  atoi(Tmp) - 1;

	memcpy(Tmp, TimeSrc + 4, 2);
	time.tm_mday =  atoi(Tmp);

	memcpy(Tmp, TimeSrc + 6, 2);
	time.tm_hour =  atoi(Tmp);

	memcpy(Tmp, TimeSrc + 8, 2);
	time.tm_min =  atoi(Tmp);

	memcpy(Tmp, TimeSrc + 10, 2);
	time.tm_sec =  atoi(Tmp);

	timep = mktime(&time);

	timep += 8 * 60 * 60;	//UTC时间改为本地时间加8个小时
	ptr=(struct tm *)localtime(&timep);

	strftime(TimeDst,40,"%Y-%m-%d %H:%M:%S",ptr);

}

//-------------------------------OBJ操作--------------------------------------

void ASN1_OBJ_init(ASN1_OBJ *pasn1_o)
{
	pasn1_o->len = 0;
	pasn1_o->tag = 0;
	pasn1_o->value = NULL;
	pasn1_o->headlen = 0;
	memset(pasn1_o->header, 0x00, sizeof(pasn1_o->header));
}

void ASN1_OBJS_init(ASN1_OBJ *pasn1_o, int count)
{
	int i = 0;
	for (i = 0; i < count; i++)
	{
		ASN1_OBJ_init(&pasn1_o[i]);
	}
}

void ASN1_OBJ_dump(ASN1_OBJ asn1_o, ASN1_OBJ *pasn1_o)
{
	if (NULL == pasn1_o) return;

	pasn1_o->len = asn1_o.len;
	pasn1_o->tag = asn1_o.tag;
	pasn1_o->value = asn1_o.value;
	pasn1_o->headlen = asn1_o.headlen;
	memcpy(pasn1_o->header, asn1_o.header, sizeof(pasn1_o->header));
}


//-------------------------------Der编码--------------------------------------

//	根据ASN1_OBJ类型的TLV构造ASN1_OBJ中的header头
int i2d_ASN1_OBJ(ASN1_OBJ *p_asn1_o)
{	
	unsigned char *ptr = NULL;
	//注意字节序问题此处有bug
	if (V_ASN1_SEQUENCE == p_asn1_o->tag)
	{
		p_asn1_o->header[0] = 0x30;
	}
	else if (V_ASN1_SET == p_asn1_o->tag)
	{
		p_asn1_o->header[0] = 0x31;
	}
	else
		p_asn1_o->header[0] = (unsigned char)p_asn1_o->tag;


	if(p_asn1_o->len < 0x0080)
	{
		p_asn1_o->header[1] = (unsigned char)p_asn1_o->len;
		p_asn1_o->headlen = 2;
	}
	else if(p_asn1_o->len <0x0100)  //0x81
	{
		p_asn1_o->header[1] = 0x81;
		p_asn1_o->header[2] = (unsigned char)p_asn1_o->len;
		p_asn1_o->headlen = 3;
	}
	else if(p_asn1_o->len <0x010000)  //0x82
	{
		
		ptr = (unsigned char *)&p_asn1_o->len;
		p_asn1_o->header[1] = 0x82;
		p_asn1_o->header[2] = ptr[1];
		p_asn1_o->header[3] = ptr[0];
		p_asn1_o->headlen = 4;
	}
	else  if(p_asn1_o->len <0x01000000) //0x83
	{
		ptr = (unsigned char *)&p_asn1_o->len;
		p_asn1_o->header[1] = 0x83;
		p_asn1_o->header[2] = ptr[2];
		p_asn1_o->header[3] = ptr[1];
		p_asn1_o->header[4] = ptr[0];
		p_asn1_o->headlen = 5;
	}
	else 
	{
		return -1;
	}

	return 0;
}

//	将ASN1_OBJ类型的数组转换为der编码数据，p_asn1_o的每个结构体成员如果tag不为0就会默认对
//	该成员再进行编码，若每个结构体成员如果tag==0，不会再单独对该成员进行编码，结果为ASN1_OBJ
int i2d_ASN1_OBJ_set(ASN1_OBJ *p_asn1_o, int count, int merge_tag, unsigned char* der_out, 
	int *p_der_len)
{
	int i = 0;
	int outlen = 0;
	int mcpyiv = 0;

	ASN1_OBJ final_obj;

	//先计算长度判断函数外部分配的内存是否够用
	for (i = 0; i < count; i++)
	{
		if (p_asn1_o[i].tag != 0)
		{
			i2d_ASN1_OBJ(&p_asn1_o[i]);
		}		
		outlen += p_asn1_o[i].headlen +p_asn1_o[i].len;
	}

	final_obj.tag = merge_tag;
	final_obj.len = outlen;

	if (i2d_ASN1_OBJ(&final_obj) < 0)
	{
		return -1;
	}


	outlen += final_obj.headlen;

	if (*p_der_len < outlen)
	{
		return -1;
	}

	if (NULL != der_out)
	{
		memcpy(der_out + mcpyiv, final_obj.header, final_obj.headlen);

		mcpyiv += final_obj.headlen;

		for (i = 0; i < count; i++)
		{
			if (0 != p_asn1_o[i].headlen)
			{
				memcpy(der_out + mcpyiv, p_asn1_o[i].header, p_asn1_o[i].headlen);
				mcpyiv += p_asn1_o[i].headlen;
			}

			memcpy(der_out + mcpyiv, p_asn1_o[i].value, p_asn1_o[i].len);
			mcpyiv += p_asn1_o[i].len;
		}

	}

	*p_der_len = outlen;

	return 0;
}

//-------------------------------Der解码--------------------------------------

//	由der编码转换为ASN1_OBJ类型(pasn1_o的头已解析)，返回ASN1_OBJ在der_in中所占用的总长度
//	(返回值大于0为正常)
int d2i_ASN1_OBJ(unsigned char* der_in, int der_len, ASN1_OBJ *p_asn1_o)
{
	int iLen = 0;

	ASN1_OBJ asn1_o;

	if (NULL == der_in)
	{
		printf("der_in is not valid\n");
		return -1;
	}
	if (0 >= der_len)
	{
		printf("der_len is not valid\n");
		return -1;
	}
	
	switch(der_in[0])
	{
	case 0x30 :
		asn1_o.tag = V_ASN1_SEQUENCE;
		break;

	case 0x31 :
		asn1_o.tag = V_ASN1_SET;
		break;

	default:
		asn1_o.tag = der_in[0];
	}

	iLen += 1;

	if (0 == der_in[1])
	{
		asn1_o.len = 0;
		asn1_o.value = NULL;
		iLen += 1;
	}
	else if (0x80 > der_in[1])
	{
		asn1_o.len = (int)der_in[1];
		asn1_o.value = &der_in[2];
		iLen += 1 + asn1_o.len;
	}
	else if (0x81 == der_in[1])
	{
		asn1_o.len = (int)der_in[2]; 
		asn1_o.value = &der_in[3];
		iLen += 2 + asn1_o.len;
	}
	else if (0x82 == der_in[1])
	{
		char * plen=(char *)&asn1_o.len;
		if (0 == TestByteOrder())
		{
			plen[0] = der_in[3];
			plen[1] = der_in[2];
			plen[2] = 0x0;
			plen[3] = 0x0;
		}
		else
		{
			plen[0] = 0x0;
			plen[1] = 0x0;
			plen[2] = der_in[2];
			plen[3] = der_in[3];
		}

		asn1_o.value = &der_in[4];
		iLen += 3 + asn1_o.len;
	}
	else if (0x83 == der_in[1])
	{
		char * plen=(char *)&asn1_o.len;
		if (0 == TestByteOrder())
		{
			plen[0] = der_in[4];
			plen[1] = der_in[3];
			plen[2] = der_in[2];
			plen[3] = 0x0;
		}
		else
		{
			plen[0] = 0x0;
			plen[1] = der_in[2];
			plen[2] = der_in[3];
			plen[3] = der_in[4];
		}
		asn1_o.value = &der_in[5];
		iLen += 4 + asn1_o.len;
	}
	else
	{
		printf("Cann't parse so long\n");
		return -1;
	}
	ASN1_OBJ_dump(asn1_o, p_asn1_o);
	
	return iLen;

}


//	由ASN1_STRING获取其下的ASN1_OBJ并解析各个ASN1_OBJ，返回der_in中ASN1_OBJ总个数
//	(返回值大于0为正常)
int d2i_ASN1_OBJ_STRING_obj(unsigned char* der_in, int der_len, ASN1_OBJ *pasn1_o)
{
	int i = 0;
	int asn1_der_len = 0;
	int obj_ptr_in_der = 0;

	for(i = 0; ; i++)
	{
		asn1_der_len = d2i_ASN1_OBJ(der_in + obj_ptr_in_der, 
			der_len - obj_ptr_in_der, &pasn1_o[i]);

		if (asn1_der_len <= 0)
		{
			return -1;
		}

		obj_ptr_in_der += asn1_der_len;

		if (obj_ptr_in_der == der_len)
		{
			return ++i;
		}
		if (obj_ptr_in_der > der_len)
		{
			return -1;
		}
	}

	return i;
}

//	由ASN1_STRING获取其下的ASN1_OBJ不解析各个ASN1_OBJ，返回der_in中ASN1_OBJ总个数
//	(返回值大于0为正常)
int d2i_ASN1_OBJ_STRING_der(unsigned char* der_in, int der_len, ASN1_OBJ *pasn1_o)
{
	int i = 0;
	int asn1_der_len = 0;
	int obj_ptr_in_der = 0;

	ASN1_OBJ asn1_obj_tmp;
	ASN1_OBJ_init(&asn1_obj_tmp);

	for(i = 0; ; i++)
	{
		asn1_der_len = d2i_ASN1_OBJ(der_in + obj_ptr_in_der, 
			der_len - obj_ptr_in_der, &asn1_obj_tmp);

		if (asn1_der_len <= 0)
		{
			return -1;
		}

		if (NULL != pasn1_o)
		{
			pasn1_o[i].value = der_in + obj_ptr_in_der;
			pasn1_o[i].len = asn1_der_len;
		}

		obj_ptr_in_der += asn1_der_len;

		if (obj_ptr_in_der == der_len)
		{
			return ++i;
		}
		if (obj_ptr_in_der > der_len)
		{
			return -1;
		}
	}

	return i;
}


//	在ASN1_STRING中查找第appear_times(大于0)个TAG == tag的ASN1_OBJ并解析该ASN1_OBJ，
//	返回该ASN1_OBJ相对der_in的偏移(返回值大于0为正常)
int d2i_ASN1_OBJ_STRING_objsearch(unsigned char* der_in, int der_len, int tag, 
	int appear_times, ASN1_OBJ *pasn1_o)
{
	int i = 0;
	int asn1_der_len = 0;
	int obj_ptr_in_der = 0;
	int appear_count = 1;

	ASN1_OBJ asn1_o_tmp;

	if (appear_times <= 0)
	{
		return -1;
	}
	if (0x30 == tag)
	{
		tag = V_ASN1_SEQUENCE;
	}
	else if (0x31 == tag)
	{
		tag = V_ASN1_SET;
	}

	for(i = 0; ; i++)
	{
		asn1_der_len = d2i_ASN1_OBJ(der_in + obj_ptr_in_der, 
			der_len - obj_ptr_in_der, &asn1_o_tmp);

		if (asn1_der_len <= 0)
		{
			return -1;
		}
		if (tag == asn1_o_tmp.tag)
		{
			if (appear_count == appear_times)
			{
				ASN1_OBJ_dump(asn1_o_tmp, pasn1_o);
				return obj_ptr_in_der;
			}
			else
				appear_count++;
		}
		obj_ptr_in_der += asn1_der_len;

		if (obj_ptr_in_der >= der_len)
		{
			return -1;
		}

	}
	
	return -1;
}

//	在ASN1_STRING中查找第appear_times(大于0)个TAG == tag的ASN1_OBJ不解析该ASN1_OBJ，
//	并返回该object相对der_in的偏移(返回值大于0为正常)
int d2i_ASN1_OBJ_STRING_dersearch(unsigned char* der_in, int der_len, int tag, 
	int appear_times, ASN1_OBJ *pasn1_o)
{
	int i = 0;
	int asn1_der_len = 0;
	int obj_ptr_in_der = 0;
	int appear_count = 1;

	ASN1_OBJ asn1_o_tmp;

	if (appear_times <= 0)
	{
		return -1;
	}
	if (0x30 == tag)
	{
		tag = V_ASN1_SEQUENCE;
	}
	else if (0x31 == tag)
	{
		tag = V_ASN1_SET;
	}

	for(i = 0; ; i++)
	{
		asn1_der_len = d2i_ASN1_OBJ(der_in + obj_ptr_in_der, 
			der_len - obj_ptr_in_der, &asn1_o_tmp);

		if (asn1_der_len <= 0)
		{
			return -1;
		}
		if (tag == asn1_o_tmp.tag)
		{
			if (appear_count == appear_times)
			{
				pasn1_o->len = asn1_der_len;
				pasn1_o->value = der_in + obj_ptr_in_der;
				pasn1_o->tag = 0;
				pasn1_o->headlen = 0;
				return obj_ptr_in_der;
			}
			else
				appear_count++;
		}
		obj_ptr_in_der += asn1_der_len;

		if (obj_ptr_in_der >= der_len)
		{
			return -1;
		}

	}

	return -1;
}

//-------------------------------X509解码--------------------------------------

//	asn1_name不含tag是未经过解析的obj(返回值等于0为正常)
int X509NameParse(ASN1_OBJ asn1_name, char *pname_str, int name_buf_len)
{
	int ret = 0;
	int i = 0;
	int item_num = 0;

	int item_CN_val_len = 0;
	int item_C_val_len = 0;
	int item_O_val_len = 0;
	int item_OU_val_len = 0;
	int item_L_val_len = 0;
	int item_S_val_len = 0;
	int item_E_val_len = 0;

	char item_CN_val[256] = {0x00};
	char item_C_val[256] = {0x00};
	char item_O_val[256] = {0x00};
	char item_OU_val[256] = {0x00};
	char item_L_val[256] = {0x00};
	char item_S_val[256] = {0x00};
	char item_E_val[256] = {0x00};

	char name_buf[2048] = {0x00};

	ASN1_OBJ asn1_obj_tmp, asn1_obj_name_item[16], asn1_obj_name_item_tmp, 
		asn1_obj_name_item_idAndval_tmp[2];

	ASN1_OBJ_init(&asn1_obj_tmp);
	ASN1_OBJ_init(&asn1_obj_name_item_tmp);
	ASN1_OBJS_init(asn1_obj_name_item, 16);
	ASN1_OBJS_init(asn1_obj_name_item_idAndval_tmp, 2);

	ret = d2i_ASN1_OBJ(asn1_name.value, asn1_name.len, &asn1_obj_tmp);
	if (ret < 0) return -1;

	item_num = d2i_ASN1_OBJ_STRING_obj(asn1_obj_tmp.value, asn1_obj_tmp.len, asn1_obj_name_item);
	if (item_num < 0) return -1;


	for(i = 0; i < item_num; i++)
	{
		ret = d2i_ASN1_OBJ(asn1_obj_name_item[i].value, asn1_obj_name_item[0].len,
			&asn1_obj_name_item_tmp);
		if (ret < 0) return -1;

		ret = d2i_ASN1_OBJ_STRING_obj(asn1_obj_name_item_tmp.value, asn1_obj_name_item_tmp.len,
			asn1_obj_name_item_idAndval_tmp);
		if (ret < 0) return -1;

		if (0 == memcmp(asn1_obj_name_item_idAndval_tmp[0].value, item_CN, sizeof(item_CN)))
		{
			if(sizeof(item_CN_val) > asn1_obj_name_item_idAndval_tmp[1].len)
				item_CN_val_len = asn1_obj_name_item_idAndval_tmp[1].len;
			else
				item_CN_val_len = sizeof(item_CN_val);

			memcpy(item_CN_val, asn1_obj_name_item_idAndval_tmp[1].value, item_CN_val_len);
		}
		else if(0 == memcmp(asn1_obj_name_item_idAndval_tmp[0].value, item_C, sizeof(item_C)))
		{
			if(sizeof(item_C_val) > asn1_obj_name_item_idAndval_tmp[1].len)
				item_C_val_len = asn1_obj_name_item_idAndval_tmp[1].len;
			else
				item_C_val_len = sizeof(item_C_val);

			memcpy(item_C_val, asn1_obj_name_item_idAndval_tmp[1].value, item_C_val_len);
		}
		else if(0 == memcmp(asn1_obj_name_item_idAndval_tmp[0].value, item_O, sizeof(item_O)))
		{
			if(sizeof(item_O_val) > asn1_obj_name_item_idAndval_tmp[1].len)
				item_O_val_len = asn1_obj_name_item_idAndval_tmp[1].len;
			else
				item_O_val_len = sizeof(item_O_val);

			memcpy(item_O_val, asn1_obj_name_item_idAndval_tmp[1].value, item_O_val_len);
		}
		else if(0 == memcmp(asn1_obj_name_item_idAndval_tmp[0].value, item_OU, sizeof(item_OU)))
		{
			if(sizeof(item_OU_val) > asn1_obj_name_item_idAndval_tmp[1].len)
				item_OU_val_len = asn1_obj_name_item_idAndval_tmp[1].len;
			else
				item_OU_val_len = sizeof(item_OU_val);

			memcpy(item_OU_val, asn1_obj_name_item_idAndval_tmp[1].value, item_OU_val_len);
		}
		else if(0 == memcmp(asn1_obj_name_item_idAndval_tmp[0].value, item_L, sizeof(item_L)))
		{
			if(sizeof(item_L_val) > asn1_obj_name_item_idAndval_tmp[1].len)
				item_L_val_len = asn1_obj_name_item_idAndval_tmp[1].len;
			else
				item_L_val_len = sizeof(item_L_val);

			memcpy(item_L_val, asn1_obj_name_item_idAndval_tmp[1].value, item_L_val_len);
		}
		else if(0 == memcmp(asn1_obj_name_item_idAndval_tmp[0].value, item_S, sizeof(item_S)))
		{
			if(sizeof(item_S_val) > asn1_obj_name_item_idAndval_tmp[1].len)
				item_S_val_len = asn1_obj_name_item_idAndval_tmp[1].len;
			else
				item_S_val_len = sizeof(item_S_val);

			memcpy(item_S_val, asn1_obj_name_item_idAndval_tmp[1].value, item_S_val_len);
		}
		else if(0 == memcmp(asn1_obj_name_item_idAndval_tmp[0].value, item_E, sizeof(item_E)))
		{
			if(sizeof(item_E_val) > asn1_obj_name_item_idAndval_tmp[1].len)
				item_E_val_len = asn1_obj_name_item_idAndval_tmp[1].len;
			else
				item_E_val_len = sizeof(item_E_val);

			memcpy(item_E_val, asn1_obj_name_item_idAndval_tmp[1].value, item_E_val_len);
		}
	}
	if(0 != item_CN_val_len)
	{
		strcat(name_buf, "CN=");
		strcat(name_buf, item_CN_val);
	}
	if (0 != item_OU_val_len)
	{
		strcat(name_buf, ",OU=");
		strcat(name_buf, item_OU_val);
	}
	if (0 != item_O_val_len)
	{
		strcat(name_buf, ",O=");
		strcat(name_buf, item_O_val);
	}
	if (0 != item_C_val_len)
	{
		strcat(name_buf, ",C=");
		strcat(name_buf, item_C_val);
	}
/*	if (0 != item_C_val_len)
	{
		strcat(name_buf, "C=");
		strcat(name_buf, item_C_val);
	}
	if(0 != item_S_val_len)
	{
		strcat(name_buf, ",S=");
		strcat(name_buf, item_S_val);
	}
	if(0 != item_L_val_len)
	{
		strcat(name_buf, ",L=");
		strcat(name_buf, item_L_val);
	}
	if (0 != item_O_val_len)
	{
		strcat(name_buf, ",O=");
		strcat(name_buf, item_O_val);
	}
	if (0 != item_OU_val_len)
	{
		strcat(name_buf, ",OU=");
		strcat(name_buf, item_OU_val);
	}
	if(0 != item_CN_val_len)
	{
		strcat(name_buf, ",CN=");
		strcat(name_buf, item_CN_val);
	}
	if(0 != item_E_val_len)
	{
		strcat(name_buf, ",E=");
		strcat(name_buf, item_E_val);
	}
*/
	if (name_buf_len > (int)strlen(name_buf))
	{
		strcpy(pname_str, name_buf);
	}
	else
	{
		return -1;
	}

	return 0;
}

//	asn1_cert不含tag是未经过解析的obj(返回值等于0为正常)
int X509CertParse(ASN1_OBJ asn1_cert, char Version[8], char SignAlg[16], char HashAlg[16],
	char *pIssuer, int IssuerBufLen, char *pSubject, int SubjectBufLen, 
	char SN[64], char NotBefore[48],char NotAfter[48], char *pPubKey, int *piPubKeyLen)
{
	int ret = 0;

	int ifpad0 = 0;

	ASN1_OBJ asn1_obj_tmp, asn1_obj_tmp1, asn1_obj_v, asn1_obj_alg,	asn1_obj_sn, 
		asn1_obj_utctmp, asn1_obj_utcseq[2], asn1_obj_issuer, asn1_obj_subject,
		asn1_obj_pubkey;

	ASN1_OBJ_init(&asn1_obj_tmp);
	ASN1_OBJ_init(&asn1_obj_tmp1);
	ASN1_OBJ_init(&asn1_obj_v);
	ASN1_OBJ_init(&asn1_obj_alg);
	ASN1_OBJ_init(&asn1_obj_pubkey);

	ASN1_OBJ_init(&asn1_obj_sn);
	ASN1_OBJ_init(&asn1_obj_utctmp);
	ASN1_OBJ_init(&asn1_obj_issuer);
	ASN1_OBJ_init(&asn1_obj_subject);

	ASN1_OBJS_init(asn1_obj_utcseq, 2);

	ret = d2i_ASN1_OBJ(asn1_cert.value, asn1_cert.len, &asn1_obj_tmp);
	if(ret < 0) return ret;
	
	if (NULL != SignAlg || NULL != HashAlg)
	{
		//解析证书中的签名摘要算法
		ret = d2i_ASN1_OBJ_STRING_objsearch(asn1_obj_tmp.value, asn1_obj_tmp.len, V_ASN1_SEQUENCE, 2, &asn1_obj_tmp1);
		if(ret < 0) return ret;
		
		ret = d2i_ASN1_OBJ(asn1_obj_tmp1.value, asn1_obj_tmp1.len, &asn1_obj_alg);
		if(ret < 0) return ret;

		if (0 == MemCmp(asn1_obj_alg.value, bSM3SM2, asn1_obj_alg.len, sizeof(bSM3SM2)))
		{
			strcpy(SignAlg, "SM2");
			strcpy(HashAlg, "SM3");
		}
		else if (0 == MemCmp(asn1_obj_alg.value, bSHA1SM2, asn1_obj_alg.len, sizeof(bSHA1SM2)))
		{
			strcpy(SignAlg, "SM2");
			strcpy(HashAlg, "SHA1");
		}
		else if (0 == MemCmp(asn1_obj_alg.value, bSHA256SM2, asn1_obj_alg.len, sizeof(bSHA256SM2)))
		{
			strcpy(SignAlg, "SM2");
			strcpy(HashAlg, "SHA256");
		}
		else if (0 == MemCmp(asn1_obj_alg.value, bMD2RSA, asn1_obj_alg.len, sizeof(bMD2RSA)))
		{
			strcpy(SignAlg, "RSA");
			strcpy(HashAlg, "MD2");
		}
		else if (0 == MemCmp(asn1_obj_alg.value, bMD4RSA, asn1_obj_alg.len, sizeof(bMD4RSA)))
		{
			strcpy(SignAlg, "RSA");
			strcpy(HashAlg, "MD4");
		}
		else if (0 == MemCmp(asn1_obj_alg.value, bMD5RSA, asn1_obj_alg.len, sizeof(bMD5RSA)))
		{
			strcpy(SignAlg, "RSA");
			strcpy(HashAlg, "MD5");
		}
		else if (0 == MemCmp(asn1_obj_alg.value, bSHA1RSA, asn1_obj_alg.len, sizeof(bSHA1RSA)))
		{
			strcpy(SignAlg, "RSA");
			strcpy(HashAlg, "SHA1");
		}
		else if (0 == MemCmp(asn1_obj_alg.value, bSHA256RSA, asn1_obj_alg.len, sizeof(bSHA256RSA)))
		{
			strcpy(SignAlg, "RSA");
			strcpy(HashAlg, "SHA256");
		}
		else if (0 == MemCmp(asn1_obj_alg.value, bSHA384RSA, asn1_obj_alg.len, sizeof(bSHA384RSA)))
		{
			strcpy(SignAlg, "RSA");
			strcpy(HashAlg, "SHA384");
		}
		else if (0 == MemCmp(asn1_obj_alg.value, bSHA512RSA, asn1_obj_alg.len, sizeof(bSHA512RSA)))
		{
			strcpy(SignAlg, "RSA");
			strcpy(HashAlg, "SHA512");
		}
		else 
			return -1;
	}
	
	
	ret = d2i_ASN1_OBJ(asn1_obj_tmp.value, asn1_obj_tmp.len, &asn1_obj_tmp);
	if(ret < 0) return ret;
	
	if (NULL != Version)
	{
		//解析证书中的版本号
		ret = d2i_ASN1_OBJ_STRING_objsearch(asn1_obj_tmp.value, asn1_obj_tmp.len, V_ASN1_ASN1_A0, 1, &asn1_obj_v);
		if(ret < 0) return ret;
		
		ret = d2i_ASN1_OBJ(asn1_obj_v.value, asn1_obj_v.len, &asn1_obj_tmp1);
		if(ret < 0) return ret;
		
		if (1 != asn1_obj_tmp1.len) return -1;
		
		sprintf(Version, "V%d", asn1_obj_tmp1.value[0] + 1);
	}

	if (NULL != SN)
	{
		//解析证书中的序列号
		ret = d2i_ASN1_OBJ_STRING_objsearch(asn1_obj_tmp.value, asn1_obj_tmp.len, V_ASN1_INTEGER, 1, &asn1_obj_sn);
		if(ret < 0) return ret;

		SprintSN(SN, asn1_obj_sn.value, asn1_obj_sn.len);
	}
	
	if (NULL != NotBefore && NULL != NotAfter)
	{
		//解析证书中的UTCtime
		ret = d2i_ASN1_OBJ_STRING_objsearch(asn1_obj_tmp.value, asn1_obj_tmp.len, V_ASN1_SEQUENCE, 3, &asn1_obj_utctmp);
		if(ret < 0) return ret;

		ret = d2i_ASN1_OBJ_STRING_obj(asn1_obj_utctmp.value, asn1_obj_utctmp.len, asn1_obj_utcseq);
		if(ret < 0) return ret;

		DerTime2Str((char*)asn1_obj_utcseq[0].value, NotBefore);
		DerTime2Str((char*)asn1_obj_utcseq[1].value, NotAfter);
	}
	
	if (NULL != pIssuer)
	{
		//解析证书中的颁发者
		ret = d2i_ASN1_OBJ_STRING_dersearch(asn1_obj_tmp.value, asn1_obj_tmp.len, V_ASN1_SEQUENCE, 2, &asn1_obj_issuer);
		if(ret < 0) return ret;

		ret = X509NameParse(asn1_obj_issuer, pIssuer, IssuerBufLen);
		if(ret < 0) return ret;
	}
	
	if (NULL != pSubject)
	{
		//解析证书中的使用者
		ret = d2i_ASN1_OBJ_STRING_dersearch(asn1_obj_tmp.value, asn1_obj_tmp.len, V_ASN1_SEQUENCE, 4, &asn1_obj_subject);
		if(ret < 0) return ret;

		ret = X509NameParse(asn1_obj_subject, pSubject, SubjectBufLen);
		if(ret < 0) return ret;
	}
	
	if (NULL != pPubKey || NULL != piPubKeyLen)
	{
		//解析证书中的公钥
		ret = d2i_ASN1_OBJ_STRING_objsearch(asn1_obj_tmp.value, asn1_obj_tmp.len, V_ASN1_SEQUENCE, 5, &asn1_obj_tmp1);
		if(ret < 0) return ret;
		
		ret = d2i_ASN1_OBJ_STRING_objsearch(asn1_obj_tmp1.value, asn1_obj_tmp1.len, V_ASN1_BIT_STRING, 1, &asn1_obj_pubkey);
		if(ret < 0) return ret;
		
		if (0x00 == asn1_obj_pubkey.value[0]) ifpad0 = 1;

		if (NULL != piPubKeyLen)
		{
			*piPubKeyLen = asn1_obj_pubkey.len - ifpad0;
		}
		if (NULL != pPubKey)
		{
			memcpy(pPubKey, &asn1_obj_pubkey.value[ifpad0], asn1_obj_pubkey.len - ifpad0);
		}
	}
	
	return 0;
}

//	asn1_cert不含tag是未经过解析的obj(返回值等于0为正常)
//	根据OID获取Extension扩展项中对应的值,注：piCritical 1为TRUE，-1为FALSE，0为无此项
int X509CertGetExt(ASN1_OBJ asn1_cert, char *pExtOid, int *piCritical, char *pValue, int *piValueLen)
{
	int ret = 0;

	int cur_ext = 0;
	int ext_num = 0;
	int item_num = 0;

	int nHexOidLen = 0;
	char pHexOid[128] = {0x00};

	ASN1_OBJ * asn1_obj_exts = NULL;
	ASN1_OBJ asn1_obj_tmp, asn1_obj_tmp1, asn1_obj_item_str, asn1_obj_ext_item[3], asn1_obj_exts_str;


	Asn1_Oid2Der(pExtOid, pHexOid, &nHexOidLen);


	ASN1_OBJ_init(&asn1_obj_tmp);
	ASN1_OBJ_init(&asn1_obj_tmp1);
	ASN1_OBJ_init(&asn1_obj_item_str);
	ASN1_OBJS_init(asn1_obj_ext_item, 3);
	ASN1_OBJ_init(&asn1_obj_exts_str);

	ret = d2i_ASN1_OBJ(asn1_cert.value, asn1_cert.len, &asn1_obj_tmp);
	if(ret < 0) return ret;

	ret = d2i_ASN1_OBJ(asn1_obj_tmp.value, asn1_obj_tmp.len, &asn1_obj_tmp);
	if(ret < 0) return ret;


	//解析证书中的扩展项
	ret = d2i_ASN1_OBJ_STRING_objsearch(asn1_obj_tmp.value, asn1_obj_tmp.len, V_ASN1_ASN1_A3, 1, &asn1_obj_tmp1);
	if(ret < 0) return ret;

	ret = d2i_ASN1_OBJ(asn1_obj_tmp1.value, asn1_obj_tmp1.len, &asn1_obj_exts_str);
	if(ret < 0) return ret;

	//获取扩展项数目
	ext_num = d2i_ASN1_OBJ_STRING_der(asn1_obj_exts_str.value, asn1_obj_exts_str.len, NULL);
	if(ret < 0) return ret;

	asn1_obj_exts = (ASN1_OBJ*)calloc(ext_num, sizeof(ASN1_OBJ));
	if (NULL == asn1_obj_exts)	return -1;


	ret = d2i_ASN1_OBJ_STRING_obj(asn1_obj_exts_str.value, asn1_obj_exts_str.len, asn1_obj_exts);
	if(ret < 0) 
	{
		free(asn1_obj_exts);
		return ret;
	}


	for (cur_ext = 0; cur_ext < ext_num; cur_ext++)
	{

		item_num = d2i_ASN1_OBJ_STRING_obj(asn1_obj_exts[cur_ext].value, asn1_obj_exts[cur_ext].len, asn1_obj_ext_item);
		if(2 != item_num && 3 != item_num) 
		{
			free(asn1_obj_exts);
			return item_num;
		}

		if (0 != MemCmp(asn1_obj_ext_item[0].value, pHexOid, asn1_obj_ext_item[0].len, nHexOidLen))
		{
			continue;
		}
		else
		{
			if (NULL != piValueLen)
			{
				*piValueLen = asn1_obj_ext_item[item_num - 1].len;
			}
			
			if (NULL != pValue)
			{
				memcpy(pValue, asn1_obj_ext_item[item_num - 1].value, asn1_obj_ext_item[item_num - 1].len);
			}

			if (3 == item_num && NULL != piCritical)
			{
				if (0xFF == asn1_obj_ext_item[1].value[0])
				{
					*piCritical = 1;
				} 
				else
				{
					*piCritical = -1;
				}
			}
			else if (NULL != piCritical)
				*piCritical = 0;

			free(asn1_obj_exts);
			return 0;
		}




	}

	free(asn1_obj_exts);
	return -1;
}


//-------------------------------P7B解析证书--------------------------------------

//	解析P7B中的各个证书，并返回证书个数(返回值大于0为正常)
int P7BCertParse(unsigned char* der_in, int der_len, ASN1_OBJ *pasn1_o)
{
	int ret = 0;
	ASN1_OBJ asn1_obj_tmp;
	ASN1_OBJ_init(&asn1_obj_tmp);


	ret = d2i_ASN1_OBJ(der_in, der_len, &asn1_obj_tmp);
	if(ret < 0 ) return -1;

	ret = d2i_ASN1_OBJ_STRING_objsearch(asn1_obj_tmp.value, asn1_obj_tmp.len, V_ASN1_ASN1_A0, 1, &asn1_obj_tmp);
	if(ret < 0 ) return -1;

	ret = d2i_ASN1_OBJ(asn1_obj_tmp.value, asn1_obj_tmp.len, &asn1_obj_tmp);
	if(ret < 0 ) return -1;

	ret = d2i_ASN1_OBJ_STRING_objsearch(asn1_obj_tmp.value, asn1_obj_tmp.len, V_ASN1_ASN1_A0, 1, &asn1_obj_tmp);
	if(ret < 0 ) return -1;

	//获取每个证书seq
	ret = d2i_ASN1_OBJ_STRING_der(asn1_obj_tmp.value, asn1_obj_tmp.len, pasn1_o);
	return ret;

}

//	从p7b中查找用户证书(返回值等于0为正常)
int UserCertSearchFromP7b(unsigned char* der_in, int der_len, unsigned char* der_out, 
	int *pout_der_len)
{
	int ret = 0;
	int i = 0, j = 0, k = 0;
	int cert_num = 0;

	char cArrSubject[8][512] = {{0x00}};
	char cArrIssuer[8][512] = {{0x00}};

	ASN1_OBJ asn1_obj_cers[8];
	ASN1_OBJS_init(asn1_obj_cers, 8);

	cert_num = P7BCertParse(der_in, der_len, asn1_obj_cers);
	if(cert_num <= 0) return -1;

	for (i = 0; i < cert_num; i++)
	{
		ret = X509CertParse(asn1_obj_cers[i], NULL, NULL, NULL, cArrIssuer[i], sizeof(cArrIssuer[i]), 
			cArrSubject[i], sizeof(cArrSubject[i]),NULL, NULL, NULL, NULL, NULL);

		if(ret < 0 ) return -1;
	}

	for(j = 0; j < cert_num; j++)
	{
		//这里用Subject和每一个Issuer比较，如果找到相同的就break，这时
		//k != cert_num  如果k == cert_num代表，没有找到和Subject相同的
		//Issuer，则代表已经找到了用户证书
		for(k = 0; k < cert_num; k++)
		{
			if(0 == strcmp(cArrSubject[j], cArrIssuer[k]))
			{
				break;
			}
		}

		//这里break代表没有找到和Subject相同的Issuer，即已经找到了用户证书
		if(k == cert_num)
		{
			break;
		}
	}

	*pout_der_len = asn1_obj_cers[j].len;
	memcpy(der_out, asn1_obj_cers[j].value, asn1_obj_cers[j].len);

	return 0;
}

//-------------------------------OID转换--------------------------------------

//	将OID字符串转换为Der编码
int Asn1_Oid2Der(char *oidstr, char *der, int *derlen)
{
	int i = 0, j = 0, k = 0;
	int der_out_iv = 0;
	char oid_buff[64] = {0x00};

	char* p_oid_section = NULL;
	int oid_section[24] = {0};
	
	char der_oid_tmp[16] = {0x00};
	
	strcpy(oid_buff, oidstr);

	//先将oid按“.”为分隔符分割为各个节，并且转化为十进制数字
	p_oid_section = strtok(oid_buff, ".");

	for(i = 0; NULL != p_oid_section; i++)
	{
		oid_section[i] = atoi(p_oid_section);
		p_oid_section  = strtok(NULL, ".");
	}

	//计算第一个字节
	der[0] = (char)( oid_section[0] * 40 + oid_section[1] );
	der_out_iv = 1;

	//计算后面的每个节转为der
	for(j = 2; j < i; j++)
	{
		for (k = 1; ;k++)
		{
			int ipow = (int)pow((float)128, k - 1);

			if (oid_section[j] < ipow)
			{
				break;
			}
			if (oid_section[j] / ipow < 128)
			{
				der_oid_tmp[16 - k] = oid_section[j] / ipow | 0x80;

				break;
			}
			else
			{
				der_oid_tmp[16 - k] =( (oid_section[j] - oid_section[j] % ipow) % (ipow * 128) )/ipow | 0x80;
			}
		}
		der_oid_tmp[15] = der_oid_tmp[15] & 0x7F;

		//将每个节的计算结果拷贝到外部
		memcpy(der + der_out_iv, &der_oid_tmp[16 - k], k);
		der_out_iv += k;

	}

	*derlen = der_out_iv;

	return 0 ;
}

//	将Der编码转换为OID字符串
int Asn1_Der2Oid(char *der, int derlen, char *oidstr)
{
	int i = 0, j = 0, k = 0;
	int der_iv = 0;
	int section_len = 1;

	int oid_section_val = 0;

	char der_buff[64] = {0x00};
	char section_buf[16] = {0x00};

	int der_section_len[16] = {0x00};
	char der_section[16][8] = {{0x00}};
	
	memcpy(der_buff, der, derlen);

	der_section[0][0] = der[0];
	der_iv++;

	for (i = 1; der_iv < derlen;)
	{
		if ( ( der_buff[der_iv + section_len - 1] | 0x80 )!=  der_buff[der_iv + section_len - 1] )
		{
			memcpy(der_section[i], &der_buff[der_iv], section_len);
			der_section_len[i] = section_len;
			der_iv += section_len;
			section_len = 1;
			i++;
			continue;
		}
		der_buff[der_iv + section_len - 1] &= 0x7F;
		section_len++;	
	}

	if (der_section[0][0] < 40)
	{
		return -1;
	}
	else
	{
		oid_section_val = der_section[0][0] / 40;
		memset(section_buf, 0x00, sizeof(section_buf));
		sprintf(section_buf, "%d.", oid_section_val);
		strcat(oidstr, section_buf);

		oid_section_val = der_section[0][0] % 40;
		memset(section_buf, 0x00, sizeof(section_buf));
		sprintf(section_buf, "%d", oid_section_val);
		strcat(oidstr, section_buf);
	}


	for (j = 1; j < i ;j++)
	{
		oid_section_val = 0;
		memset(section_buf, 0x00, sizeof(section_buf));

		for (k = 0; k < der_section_len[j]; k++)
		{
			oid_section_val += der_section[j][k] * ((int)pow((float)128, der_section_len[j] - k - 1));
		}
		
		sprintf(section_buf, "%d", oid_section_val);

		strcat(oidstr, ".");
		strcat(oidstr, section_buf);
	}



	return 0;

}



