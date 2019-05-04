// Free Disassembler and Assembler -- Demo program
//
// Copyright (C) 2001 Oleh Yuschuk
//
//  This program is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation; either version 2 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program; if not, write to the Free Software
//  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
/*
int Assemble(char *cmd,ulong ip,t_asmmodel *model,int attempt,int constsize,char *errtext)  - ���ı�������Ϊ�����ƴ���
int Checkcondition(int code,ulong flags) - checks whether flags met condition in the command  - ����������Ƿ���������
int Decodeaddress(ulong addr,ulong base,int addrmode,char *symb,int nsymb,char *comment) - �û��ṩ�ĺ���������ַ����Ϊ��������
ulong Disasm(char *src,ulong srcsize,ulong srcip,t_disasm *disasm,int disasmmode) - ȷ������������ĳ��Ȼ��䷴��ൽ�ı���
ulong Disassembleback(char *block,ulong base,ulong size,ulong ip,int n) -  ����߶����ƴ���;
ulong Disassembleforward(char *block,ulong base,ulong size,ulong ip,int n) - ��ǰ�߶����ƴ���;
int Isfilling(ulong addr,char *data,ulong size,ulong align) - ȷ�������Ƿ����NOP;
int Print3dnow(char *s,char *f) - ת��3DNow������Ϊ�ı�����������Ч��������FPU�쳣;
int Printfloat10(char *s,long double ext) - ��10�ֽڸ��㳣��ת��Ϊ�ı������ᵼ���쳣;
int Printfloat4(char *s,float f) - ��4�ֽڸ��㳣��ת��Ϊ�ı������ᵼ���쳣;
int Printfloat8(char *s,double d) - ��8�ֽڸ��㳣��ת��Ϊ�ı������ᵼ���쳣.
*/

#define STRICT
#define MAINPROG                       // Place all unique variables here

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
//#include <dir.h>
#include <math.h>
#include <float.h>
#pragma hdrstop

#include "disasm.h"

int main(main) 
{
	int i=0,j=0,n=0;
	char* pasm = {0};
	char s[TEXTLEN] = { 0 }, errtext[TEXTLEN] = {0};
	ulong l=0;
	t_disasm da = {0};
	t_asmmodel am = {0};
	BYTE buf[65 + 8] =
	{
		/*0xC6 ,0x84 ,0x24 ,0xD0 ,03 ,00 ,00 ,00,*/
		0xff,0xE0,0x55,0x8B,0xEC,0x51,0x51,0x53,0x56,0x57,\
		0x64,0x8B,0x35,0x00,0x00,0x00,0x00,0x89,0x75,0xFC,\
		0xC7,0x45,0xF8,0xF4,0x25,0xd2,0x00,0x6A,0x00,0xFF,\
		0x75,0x0C,0xFF,0x75,0xF8,0xFF,0x75,0x08,0xE8,0x76,\
		0x1F,0x01,0x00,0x8B,0x45,0x0C,0x8B,0x40,0x04,0x83,\
		0xE0,0xFD,0x8B,0x4D,0x0C,0x89,0x41,0x04,0x64,0x8B,\
		0x3D,0x00,0x00,0x00,0x00
	};
	printf("\
			=====================================================\r\n");
	char* str = "\
			  0xff,0xE0,0x55,0x8B,0xEC,0x51,0x51,0x53,0x56,0x57,\r\n\
			  0x64,0x8B,0x35,0x00,0x00,0x00,0x00,0x89,0x75,0xFC,\r\n\
			  0xC7,0x45,0xF8,0xF4,0x25,0x42,0x00,0x6A,0x00,0xFF,\r\n\
			  0x75,0x0C,0xFF,0x75,0xF8,0xFF,0x75,0x08,0xE8,0x76,\r\n\
			  0x1F,0x01,0x00,0x8B,0x45,0x0C,0x8B,0x40,0x04,0x83,\r\n\
			  0xE0,0xFD,0x8B,0x4D,0x0C,0x89,0x41,0x04,0x64,0x8B,\r\n\
			  0x3D,0x00,0x00,0x00,0x00\r\n��������������ݵķ����:\r\n";
	printf(str);
	for (unsigned long i = 0; i < 65;)
	{
		l = Disasm32(buf, &da, 0x410000, 4);
		i += l;
		printf("%08x  %-24s%-8s%-30s;%-3ibyte\r\n", da.ip, da.dump, da.cmdstr, da.result, da.bytes);
	}
	printf("\r\n=============================================================================\r\nCALL 45187C �����\r\n\n");
	// CALL 45187C �����
	l = Disasm("\xE8\x1F\x14\x00\x00",
		5, 0x450458, &da, 3);
	printf("%3i  %-24s%-8s%-20s   jmpconst=%4X\r\n", l, da.dump, da.cmdstr, da.result, da.jmpconst);
	printf("\r\n=============================================================================\r\nJNZ 450517 �����\r\n\n");
	// JNZ 450517 �ķ����
	l = Disasm("\x75\x72",
		2, 0xD504A300, &da, DISASM_CODE);
	printf("%3i  %-24s%-8s%-20s   jmpconst=%4X\r\n", l, da.dump, da.cmdstr, da.result, da.jmpconst);

	printf("\r\n=============================================================================\r\n");







	//�����������ʾ��
	printf("\nAssembler:\r\n");

	//����ȷ������Ĵ�С��
	printf("\r\n=============================================================================\r\n����ȷ������Ĵ�С\r\n\n");
	l=Disasm("\x81\x05\xE0\x5A\x47\x00\x01\x00\x00\x00\x11\x22\x33\x44\x55\x66",10,0x400000,&da,DISASM_SIZE);
	printf("����Ĵ�С = %i bytes\n",l);

	printf("\r\n=============================================================================\r\nADD [DWORD 475AE0],1\r\n");
	pasm = "ADD [DWORD 475AE0],1";
	j = Assemble(pasm, 0x400000, &am, 0, 0, errtext);
	n = sprintf(s, "%3i  ", j);
	for (i = 0; i < j; i++) n += sprintf(s + n, "%02X ", am.code[i]);
	if (j <= 0) sprintf(s + n, "  error=\"%s\"", errtext);
	printf("32λ������:%s\r\n", s);

	printf("\r\n=============================================================================\r\nADD [DWORD 475AE0],1\r\n");
	j = Assemble(pasm, 0x400000, &am, 0, 2, errtext);
	n = sprintf(s, "%3i  ", j);
	for (i = 0; i < j; i++) n += sprintf(s + n, "%02X ", am.code[i]);
	if (j <= 0) sprintf(s + n, "  error=\"%s\"", errtext);
	printf(" 8λ������:%s\r\n", s);

	printf("\r\n=============================================================================\r\n�޸�����һ�䱾�������,���صĳ�������һ��������ĳ��ȵĸ���\r\n");
	pasm = "push 7f";
	printf("%s\r\n", pasm);
	j = Assemble(pasm, 0x400000, &am, 0, 2, errtext);
	n = sprintf(s, "%3i  ", j);
	for (i = 0; i < j; i++) n += sprintf(s + n, "%02X ", am.code[i]);
	if (j <= 0) sprintf(s + n, "  error=\"%s\"", errtext);
	printf("%s\r\n", s);
	printf("\r\n=============================================================================\r\n�޸�����һ�䱾������������ A1 00 E0 04 00\r\n");
	pasm = "mov eax,dword ptr [40E000]";
	printf("%s\n", pasm);
	j = Assemble(pasm, 0x400000, &am, 0, 2, errtext);
	n = sprintf(s, "%3i  ", j);
	for (i = 0; i < j; i++) n += sprintf(s + n, "%02X ", am.code[i]);
	if (j <= 0) sprintf(s + n, "  error=\"%s\"", errtext);
	printf("%s\n", s);
	printf("\r\n=============================================================================\r\n");
	// Show results.
	return 0;
};
