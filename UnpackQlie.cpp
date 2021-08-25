#include <iostream>
#include <Windows.h>
#include <string>
#include <mmintrin.h>
#include <stack>
using namespace std;
struct FilePackVer
{
	char sign[0x10];
	DWORD filecount;
	int entry_low;
	int entry_high;
};
struct HashData
{
	char sign[0x20];
	DWORD HashVerSize;
	char data[0x100];
	DWORD Unkown;
	char Blank[0x2F8];
	FilePackVer fpacker;
};
struct Dencrypt2DataHead
{
	DWORD sign;
	DWORD isWordType;
	DWORD size;
};
struct Dencrypt2DataOutput
{
	BYTE* data;
	DWORD len;
};
struct FileEntry
{
	DWORD offset_low;
	DWORD offset_hight;
	DWORD size;
	DWORD dencrypted_size;
	DWORD isCompressed;
	DWORD EncryptType; // 0未加密 1第一种加密算法 2为第二种加密算法
	DWORD hash;
};
DWORD Tohash(void* data, int len)
{
	if (len < 8)
	{
		return 0;
	}
	//准备工作
	__m64 mm0 = _mm_cvtsi32_si64(0);
	__m64 mm1;
	__m64 mm2 = _mm_cvtsi32_si64(0);
	DWORD key = 0xA35793A7;
	__m64 mm3 = _mm_cvtsi32_si64(key);
	 mm3 = _m_punpckldq(mm3, mm3);
	 __m64* pdata=(__m64*)data;
	//开始循环计算hash
	for (size_t i = 0; i < (len >> 3); i++)
	{
		mm1 = *pdata;
		pdata++;
		mm2 = _m_paddw(mm2, mm3);
		mm1 = _m_pxor(mm1, mm2);
		mm0 = _m_paddw(mm0, mm1);
		mm1 = mm0;
		mm0 = _m_pslldi(mm0, 3);
		mm1 = _m_psrldi(mm1, 0x1D);
		mm0 = _m_por(mm1, mm0);
	}
	mm1 = _m_psrlqi(mm0, 32);
	DWORD result = _mm_cvtsi64_si32(_m_pmaddwd(mm0, mm1));
	_m_empty();//复位浮点寄存器
	return result;
}
void dencrypt(void* data,unsigned int len, DWORD hash)
{
	if (len >> 3 == 0)
	{
		return;
	}
	//准备工作
	DWORD key1 = 0xA73C5F9D;
	DWORD key2 = 0xCE24F523;
	DWORD key3 = (len + hash)^ 0xFEC9753E;
	__m64 mm7 = _mm_cvtsi32_si64(key1);
	mm7 = _m_punpckldq(mm7, mm7);
	__m64 mm6 = _mm_cvtsi32_si64(key2);
	mm6 = _m_punpckldq(mm6, mm6);
	__m64 mm5 = _mm_cvtsi32_si64(key3);
	mm5 = _m_punpckldq(mm5, mm5);
	__m64* datapos = (__m64*)data;
	__m64 mm0;
	for (size_t i = 0; i < len >> 3; i++)
	{
		mm7 = _m_paddd(mm7, mm6);
		mm7 = _m_pxor(mm7, mm5);
		mm0 = *datapos;
		mm0 = _m_pxor(mm0, mm7);
		mm5 = mm0;
		*datapos = mm0;
		datapos++;
	}
	_m_empty();//复位浮点寄存器
	return;
}
Dencrypt2DataOutput* dencrypt2(void* data, unsigned int len,unsigned int dencrypted_len, DWORD hash)
{
	char Sampletable[0x100],table[0x100],other[0x100];
	for (size_t i = 0; i < 0x100; i++)
	{
		Sampletable[i] = i;
	}
	Dencrypt2DataHead* head = (Dencrypt2DataHead*)data;
	//对比开头是否为0xFF425031
	if (head->sign != 0xFF435031)
	{
		cout << "数据不符合解码条件" << endl;
		return nullptr;
	}
	if (head->size> 0x20000000u)
	{
		cout << "数据量大于0x20000000" << endl;
		return nullptr;
	}

	Dencrypt2DataOutput* Output = new Dencrypt2DataOutput();
	Output->len = dencrypted_len;
	Output->data = new BYTE[dencrypted_len + 1];
	BYTE* outputbuff = Output->data;

	BYTE* datapos = (BYTE*)data + sizeof(Dencrypt2DataHead);
	BYTE* data_start = datapos;
	BYTE* data_end = (BYTE*)data + len;
	BYTE chr;
	int t_pos;
	int size;
	while (data_start < data_end)
	{
		chr = *data_start;
		datapos = data_start + 1;
		memcpy(table, Sampletable, 0x100);
		t_pos = 0;
		//建表循环
		while (1)
		{
			if (chr > 0x7Fu)
			{
				t_pos += chr - 127;
				chr = 0;
			}
			if (t_pos > 0xFF)
			{
				break;
			}

			for (size_t i = 0; i < chr + 1; i++)
			{
				table[t_pos] = *datapos++;
				if (t_pos != (unsigned __int8)table[t_pos])
				{
					other[t_pos] = *datapos++;
				}

				++t_pos;
			}
			if (t_pos > 0xFF)
			{
				break;
			}
			chr = *datapos++;
		}
		//数据类型判断
		if ((head->isWordType & 1) == 1)
		{
			size = *(WORD*)datapos;
			data_start = (datapos + 2);
		}
		else
		{
			size = *(DWORD*)datapos;
			data_start = (datapos + 4);
		}
		//解密循环
		stack<BYTE> stack;
		while (1)
		{
			BYTE result;
			if (stack.size())
			{
				result = stack.top();
				stack.pop();
			}
			else
			{
				if (!size)
				{
					break;
				}
				size--;
				result = *data_start;
				data_start++;
			}
			if (result == (BYTE)table[result])
			{
				*outputbuff = result;
				outputbuff++;
			}
			else
			{
				stack.push(other[result]);
				stack.push(table[result]);
			}
		}
	}
	return Output;
}
void DencryptFileName(void* data,int character_count,DWORD hash)
{
	int key = ((hash >> 0x10) & 0xFFFF) ^ hash;
	key = character_count ^ 0x3E13 ^ key ^ (character_count * character_count);
	DWORD ebx = key;
	DWORD ecx;
	WORD* datapos = (WORD*)data;
	for (size_t i = 0; i < character_count; i++)
	{
		ebx = ebx << 3;
		ecx = (ebx + i + key) & 0xFFFF;
		ebx = ecx;
		*datapos = (*datapos ^ ebx) & 0xFFFF;
		datapos++;
	}
}
DWORD* dencrypt3_hash(int hashlen,int datalen,void* filename,int character_count,DWORD hash)
{
	DWORD key1 = 0x85F532; //ebx
	DWORD key2 = 0x33F641; //esi
	WORD* character = (WORD*)filename;
	for (size_t i = 0; i < character_count; i++)
	{
		key1 = key1 + (*character << (i & 7));
		key2 ^= key1;
		character++;
	}
	DWORD key3 = (datalen ^ key1 ^ 0x8F32DC) + key1 + datalen; //eax
	DWORD key4 = ((datalen & 0xFFFFFF) << 3) - datalen; //edx
	key3 += key4;
	key3 ^= hash;
	key3 = ((key3 + key2) & 0xFFFFFF) * 9;
	//第二个计算函数
	unsigned long long rax = key3;
	DWORD* result = new DWORD[hashlen];
	for (size_t i = 0; i < hashlen; i++)
	{
		rax = (unsigned long long)(rax ^ 0x8DF21431u) * (unsigned long long)0x8DF21431u;
		rax = ((rax & 0xFFFFFFFF00000000) >> 32) + (rax & 0xFFFFFFFF);
		rax = rax & 0xFFFFFFFF;
		result[i] = rax;
	}


	return result;
}
void dencrypt3(void* data,int len, void* filekey)
{
	//0x34相当于4字节数据+0xD
	DWORD key1 = (*((DWORD*)filekey + 0xD) & 0xF) << 3;
	BYTE* datapos = (BYTE*)data, * fkey = (BYTE*)filekey;
	__m64 mm7 = *((__m64*)filekey + 0x3); //这里0x3相当于BYTE的0x18
	__m64 mm6, mm0, mm1;
	for (size_t i = 0; i < len >>3; i++)
	{
		mm6 = *(__m64*)(fkey + key1);
		mm7 = _m_pxor(mm7, mm6);
		mm7 = _m_paddd(mm7, mm6);
		mm0 = *(__m64*)datapos;
		mm0 = _m_pxor(mm0, mm7);
		mm1 = mm0;
		*(__m64*)datapos = mm0;
		mm7 = _m_paddb(mm7, mm1);
		mm7 = _m_pxor(mm7, mm1);
		mm7 = _m_pslldi(mm7, 0x1);
		mm7 = _m_paddw(mm7, mm1);
		datapos += 8;
		key1 = (key1 + 8) & 0x7F;
	}
	_m_empty();
	return;
}
BYTE* dencypt4_keyfilehash(void* data,int len)
{
	int* keyfilehash = new int[0x100];
	int* keyfilehash_pos = keyfilehash;
	//keyhash初始数据的计算
	for (size_t i = 0; i < 0x100; i++)
	{
		if (i % 3 ==0)
		{
			*keyfilehash_pos = (i + 3u) * (i + 7u);
		}
		else
		{
			*keyfilehash_pos = -(i + 3u) * (i + 7u);
		}
		keyfilehash_pos++;
	}
	int key1 = *(BYTE*)((BYTE*)data + 0x31);
	key1 = (key1 % 0x49) + 0x80;
	int key2 = *(BYTE*)((BYTE*)data + 0x1E + 0x31);
	key2 = (key2 % 7) + 7;
	BYTE* keyfilehash_pos_byte = (BYTE*)keyfilehash;
	for (size_t i = 0; i < 0x400; i++)
	{
		key1 = (key1 + key2) % len;
		*keyfilehash_pos_byte ^= *(BYTE*)((BYTE*)data + key1);
		keyfilehash_pos_byte++;
	}
	return (BYTE*)keyfilehash;
}
DWORD* dencrypt4_hash(int hashlen, int datalen, void* filename, int character_count, DWORD hash)
{
	DWORD key1 = 0x86F7E2; //ebx
	DWORD key2 = 0x4437F1; //esi
	WORD* character = (WORD*)filename;
	for (size_t i = 0; i < character_count; i++)
	{
		key1 = key1 + (*character << (i & 7));
		key2 ^= key1;
		character++;
	}
	DWORD key3 = (datalen ^ key1 ^ 0x56E213) + key1 + datalen; //eax
	int key4 = (datalen & 0xFFFFFF) * 0xD; //edx
	key3 += key4;
	key3 ^= hash;
	key3 = ((key3 + key2) & 0xFFFFFF) * 0xD;
	//第二个计算函数
	unsigned long long rax = key3;
	DWORD* result = new DWORD[hashlen];
	for (size_t i = 0; i < hashlen; i++)
	{
		rax = (unsigned long long)(rax ^ 0x8A77F473u) * (unsigned long long)0x8A77F473u;
		rax = ((rax & 0xFFFFFFFF00000000) >> 32) + (rax & 0xFFFFFFFF);
		rax = rax & 0xFFFFFFFF;
		result[i] = rax;
	}


	return result;
}
void dencrypt4(void* data, int len, void* filekey,void* keyfilehash)
{
	//0x20相当于4字节数据+0x8
	DWORD key1 = (*((DWORD*)filekey + 0x8) & 0xD) << 3;
	BYTE* datapos = (BYTE*)data, * fkey = (BYTE*)filekey,* keyfilekey = (BYTE*)keyfilehash;
	__m64 mm7 = *((__m64*)filekey + 0x3); //这里0x3相当于BYTE的0x18
	__m64 mm6, mm0, mm1,mm5;
	for (size_t i = 0; i < len >> 3; i++)
	{
		mm6 = *(__m64*)(fkey + ((key1 & 0xF) << 3));
		mm5 = *(__m64*)(keyfilekey + ((key1 & 0x7F) << 3));
		mm6 = _m_pxor(mm6, mm5);
		mm7 = _m_pxor(mm7, mm6);
		mm7 = _m_paddd(mm7, mm6);
		mm0 = *(__m64*)datapos;
		mm0 = _m_pxor(mm0, mm7);
		mm1 = mm0;
		*(__m64*)datapos = mm0;
		mm7 = _m_paddb(mm7, mm1);
		mm7 = _m_pxor(mm7, mm1);
		mm7 = _m_pslldi(mm7, 0x1);
		mm7 = _m_paddw(mm7, mm1);
		datapos += 8;
		key1 = (key1 + 1) & 0x7F;
	}
	_m_empty();
	return;
}
FILE* WideChar_CreateFile(const wchar_t* filename)
{
	wchar_t* pos = (wchar_t*)filename;
	while (1)
	{
		pos = wcschr(pos, '\\');
		if (pos == nullptr)
		{
			break;
		}
		wchar_t* dir = new wchar_t[pos - filename + 1]();
		wcsncpy(dir, filename, pos - filename);
		_wmkdir(dir);
		pos++;
		delete dir;
	}
	FILE* hfile = _wfopen(filename, L"wb");
	return hfile;
}
int main()
{
	string filename;
	cin >> filename;
	FILE* hfile;
	hfile = fopen(filename.c_str(), "rb");
	//获取文件大小,支持大于4GB文件
	_fseeki64(hfile, 0, 2);
	fpos_t file_size = _ftelli64(hfile);
	//读取filepack头
	_fseeki64(hfile, file_size - 0x1C, 0);
	FilePackVer* filepacker = new FilePackVer();
	fread(filepacker, 0x1C,1 , hfile);
	if (string(filepacker->sign) != "FilePackVer3.1\x00\x00")
	{
		cout << "FilePackVer签名验证失败" << endl;
		return 0;
	}
	//读取HashData
	HashData *hashdat = new HashData();
	_fseeki64(hfile,file_size-0x440,0);
	fread(hashdat,1,0x440,hfile);
	//数据的设置
	if (hashdat->Unkown > 8 || hashdat->Unkown < 0)
	{
		hashdat->Unkown = 0;
	}
	DWORD hash = Tohash(&hashdat->data,0x100) & 0x0FFFFFFF;
	//HashVer里的数据对解包并不重要 直接略过不按照程序一样去读取了


	/////////////////////////////////
	//解码签名
	dencrypt(&hashdat->sign, 0x20, hash);
	if (strncmp(hashdat->sign,"8hr48uky,8ugi8ewra4g8d5vbf5hb5s6",0x20))
	{
		cout << "HashData签名验证失败" << endl;
		return 0;
	}
	//开始解密文件
	
	DWORD64 entry = ((long long)filepacker->entry_high << 32) + (long long)filepacker->entry_low;
	BYTE* keyfilehash = nullptr;
	for (size_t i = 0; i < filepacker->filecount; i++)
	{
		_fseeki64(hfile, entry, 0);
		WORD character_count;
		fread(&character_count, 2, 1, hfile);
		wchar_t* name = new wchar_t[character_count + 1]();
		//因为UTF16字节数是ASCII的两倍，所以要乘2
		fread(name, 1, 2 * character_count, hfile);
		//解密文件名
		DencryptFileName(name, character_count, hash);
		FileEntry *fentry = new FileEntry();
		fread(fentry, 1, 0x1C, hfile);
		entry = _ftelli64(hfile);
		//文件名hash校检 不重要 略过

		//文件读取
		char* filedata = new char[fentry->size];
		_fseeki64(hfile, ((long long)fentry->offset_hight << 32) + (long long)fentry->offset_low, 0);
		fread(filedata, fentry->size, 1, hfile);

		//解密文件
		DWORD* filehash = nullptr;
		if (fentry->EncryptType == 1)
		{
			filehash = dencrypt3_hash(0x40, fentry->size, name, character_count, hash);
			dencrypt3(filedata, fentry->size, filehash);
			if (wcsncmp(name, L"pack_keyfile_kfueheish15538fa9or.key", character_count) == 0)
			{
				keyfilehash = dencypt4_keyfilehash(filedata, fentry->size);
			}
		}
		else if(fentry->EncryptType == 2)
		{
			filehash = dencrypt4_hash(0x40, fentry->size, name, character_count, hash);
			dencrypt4(filedata, fentry->size, filehash, keyfilehash);
		}
		Dencrypt2DataOutput* Output = nullptr;
		if (fentry->isCompressed)
		{
			Output = dencrypt2(filedata, fentry->size, fentry->dencrypted_size, hash);
		}
		else
		{
			Output = new Dencrypt2DataOutput();
			Output->data = (BYTE*)filedata;
			Output->len = fentry->dencrypted_size;
		}
		//保存文件
		wstring filename = wstring(name);
		filename = L"Extract\\" + filename;
		FILE* hOut = WideChar_CreateFile(filename.c_str());
		std::fwrite(Output->data, Output->len, 1, hOut);
		std::fclose(hOut);
		delete fentry, name, filedata, filehash, Output;
	}

	std::fclose(hfile);
}