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
	int i,j,n;
	char* pasm;
	char s[TEXTLEN], errtext[TEXTLEN];
	ulong l;
	t_disasm da;
	t_asmmodel am;

//�����������ʾ��
  printf("�����:\n");

  //����ȷ������Ĵ�С��
  l=Disasm("\x81\x05\xE0\x5A\x47\x00\x01\x00\x00\x00\x11\x22\x33\x44\x55\x66",10,0x400000,&da,DISASM_SIZE);
  printf("����Ĵ�С = %i bytes\n",l);

  // ADD [475AE0],1 MASM ģʽ, ����ʾĬ�϶�
  ideal = 0; lowercase = 1; putdefseg = 0;
  l=Disasm("\x81\x05\xE0\x5A\x47\x00\x01\x00\x00\x00",10,0x400000,&da,DISASM_CODE);
  printf("%3i  %-24s  %-24s   (MASM)\n",l,da.dump,da.result);

  // ADD [475AE0],1 IDEAL ģʽ, ��д, ��ʾĬ�϶�
  ideal=1; lowercase=0; putdefseg=1;
  l=Disasm("\x81\x05\xE0\x5A\x47\x00\x01\x00\x00\x00",10,0x400000,&da,DISASM_CODE);
  printf("%3i  %-24s  %-24s   (IDEAL)\n",l,da.dump,da.result);

  // CALL 45187C
  l=Disasm("\xE8\x1F\x14\x00\x00",5,0x450458,&da,DISASM_CODE);
  printf("%3i  %-24s  %-24s   jmpconst=%08X\n",l,da.dump,da.result,da.jmpconst);

  // JNZ 450517
  l=Disasm("\x75\x72",2,0x4504A3,&da,DISASM_CODE);
  printf("%3i  %-24s  %-24s   jmpconst=%08X\n",l,da.dump,da.result,da.jmpconst);

  // ���������ʾ
  printf("\n���:\n");

  // ������������. ��װ���������֮һ�� ����ʹ��32λ����
  pasm="ADD [DWORD 475AE0],1";
  printf("%s:\n",pasm);
  j=Assemble(pasm,0x400000,&am,0,0,errtext);
  n=sprintf(s,"%3i  ",j);
  for (i=0; i<j; i++) n+=sprintf(s+n,"%02X ",am.code[i]);
  if (j<=0) sprintf(s+n,"  error=\"%s\"",errtext);
  printf("%s\n",s);

  // Ȼ���������8λ������
  j=Assemble(pasm,0x400000,&am,0,2,errtext);
  n=sprintf(s,"%3i  ",j);
  for (i=0; i<j; i++) n+=sprintf(s+n,"%02X ",am.code[i]);
  if (j<=0) sprintf(s+n,"  error=\"%s\"",errtext);
  printf("%s\n",s);

  //�����޷�ȷ���������Ĵ�С
  pasm="add dword ptr ds:[0x475AE0],0x1";//ԭ��:pasm="MOV [475AE0],20";
  printf("%s:\n",pasm);
  j=Assemble(pasm,0x400000,&am,0,4,errtext);
  n=sprintf(s,"%3i  ",j);
  for (i=0; i<j; i++) n+=sprintf(s+n,"%02X ",am.code[i]);
  if (j<=0) sprintf(s+n,"  error=\"%s\"",errtext);
  printf("%s\n",s);

  // Show results.
  Sleep(1000);
  return 0;
};
