#include <iostream>
#include <windows.h>
#include <wincrypt.h>
using namespace std;

#define ENCRYPT_ALG CALG_RC4
#define KEYLENGTH 0x08000000

void travers_dir(TCHAR ROOTPATH[MAX_PATH+1], int LEVEL)
{
	HANDLE hFind;
	WIN32_FIND_DATA OBJECT;
	TCHAR CD[MAX_PATH+1];
	strcpy(CD, ROOTPATH);
	strcat(CD,"\\*");
	hFind = FindFirstFile(CD,&OBJECT);
	
	if(hFind==INVALID_HANDLE_VALUE)
	{
		cout<<"Couldn't retrive file handle.."<<endl;
	}
	else
	{
		do
		{
			if(strcmp(OBJECT.cFileName,".")!=0)
			{
				if(strcmp(OBJECT.cFileName,"..")!=0)
				{
					for(int i=0;i<LEVEL; i++) { cout<<" "; };
					cout<<"|- "<<OBJECT.cFileName<<endl;
					if(OBJECT.dwFileAttributes == FILE_ATTRIBUTE_DIRECTORY)
					{
						strcpy(CD, ROOTPATH);
						strcat(CD,"\\");
						strcat(CD,OBJECT.cFileName);						
						travers_dir(CD,LEVEL+1);
					}
				}
			}
		}while(FindNextFile(hFind,&OBJECT));
		FindClose(hFind);
	}
	
};

int main(int argc, char** argv)
{
	HCRYPTPROV hCryptProv;
	HCRYPTKEY  cryptSessionKey,CryptUserKey;
	TCHAR cryptContainer[100]="TestContainer";
	DWORD cryptProvType=PROV_RSA_FULL;
	DWORD cryptKeyBlobSize;
	
	system("cls");
	
/*------------------------------- Acquire Cryptographic context -------------------------------*/
	if(CryptAcquireContext(&hCryptProv,cryptContainer,NULL,cryptProvType,0))
	{
		cout<<"Container "<<cryptContainer<<" found. Cryptographic context aquisition successful."<<endl;
	}
	else
	{
		cout<<"Container "<<cryptContainer<<" not found. Attempting to create the same."<<endl;
		if(CryptAcquireContext(&hCryptProv,cryptContainer,NULL,cryptProvType,CRYPT_NEWKEYSET))
		{
			cout<<"Container "<<cryptContainer<<" created. Cryptographic context aquisition successful."<<endl;
		}
		else
		{
			cout<<"Failed to create new keyset. Aborting execution."<<GetLastError()<<endl;
			goto EXIT_PROGRAM;
		}
	}
	
/*------------------------------- Generate Session Keys -------------------------------*/
	if(!CryptGenKey(hCryptProv,ENCRYPT_ALG,KEYLENGTH|CRYPT_EXPORTABLE,&cryptSessionKey))
	{
		cout<<"Unable to generate session keys. "<<GetLastError()<<endl;
		goto EXIT_PROGRAM;
	}

/*------------------------------- Get Users Exchange(Public) key -------------------------------*/
	if(!CryptGetUserKey(hCryptProv,AT_KEYEXCHANGE,&CryptUserKey))
	{
		cout<<"Error while getting exchange keys. "<<GetLastError()<<endl;
		goto EXIT_PROGRAM;
	}
	
/*-------------------------------  Export User's keys -------------------------------*/
	CryptExportKey(cryptSessionKey,cryptUserKey,SIMPLEBLOB,0,NULL,&cryptKeyBlobSize) //Get key BLOB size
	
//	travers_dir("D:\\Reference\\CCPP\\Test",0);
	EXIT_PROGRAM:
		
/*------------------------------- Destroy Session Keys -------------------------------*/
	if(cryptKey)
	{
		if(!CryptDestroyKey(cryptKey))
		{
			cout<<"Error while destroying session keys. "<<GetLastError()<<endl;
		}
	}
	
/*------------------------------- Release Cryptographic Context -------------------------------*/
	if(hCryptProv)
	{
		if(!CryptReleaseContext(hCryptProv,0))
		{
			cout<<"Cryptographic context release failed. "<<GetLastError()<<endl;
		}
	}
	return 0;
}

/*------------------------------- End of Program -------------------------------*/
