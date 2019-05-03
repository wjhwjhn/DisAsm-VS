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
int Assemble(char *cmd,ulong ip,t_asmmodel *model,int attempt,int constsize,char *errtext)  - 将文本命令汇编为二进制代码
int Checkcondition(int code,ulong flags) - checks whether flags met condition in the command  - 检查命令中是否满足条件
int Decodeaddress(ulong addr,ulong base,int addrmode,char *symb,int nsymb,char *comment) - 用户提供的函数，将地址解码为符号名称
ulong Disasm(char *src,ulong srcsize,ulong srcip,t_disasm *disasm,int disasmmode) - 确定二进制命令的长度或将其反汇编到文本中
ulong Disassembleback(char *block,ulong base,ulong size,ulong ip,int n) -  向后走二进制代码;
ulong Disassembleforward(char *block,ulong base,ulong size,ulong ip,int n) - 向前走二进制代码;
int Isfilling(ulong addr,char *data,ulong size,ulong align) - 确定命令是否等于NOP;
int Print3dnow(char *s,char *f) - 转换3DNow！常量为文本而不触发无效操作数的FPU异常;
int Printfloat10(char *s,long double ext) - 将10字节浮点常量转换为文本而不会导致异常;
int Printfloat4(char *s,float f) - 将4字节浮点常量转换为文本而不会导致异常;
int Printfloat8(char *s,double d) - 将8字节浮点常量转换为文本而不会导致异常.
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

//反汇编程序的演示。
  printf("反汇编:\n");

  //快速确定命令的大小。
  l=Disasm("\x81\x05\xE0\x5A\x47\x00\x01\x00\x00\x00\x11\x22\x33\x44\x55\x66",10,0x400000,&da,DISASM_SIZE);
  printf("命令的大小 = %i bytes\n",l);

  // ADD [475AE0],1 MASM 模式, 不显示默认段
  ideal = 0; lowercase = 1; putdefseg = 0;
  l=Disasm("\x81\x05\xE0\x5A\x47\x00\x01\x00\x00\x00",10,0x400000,&da,DISASM_CODE);
  printf("%3i  %-24s  %-24s   (MASM)\n",l,da.dump,da.result);

  // ADD [475AE0],1 IDEAL 模式, 大写, 显示默认段
  ideal=1; lowercase=0; putdefseg=1;
  l=Disasm("\x81\x05\xE0\x5A\x47\x00\x01\x00\x00\x00",10,0x400000,&da,DISASM_CODE);
  printf("%3i  %-24s  %-24s   (IDEAL)\n",l,da.dump,da.result);

  // CALL 45187C
  l=Disasm("\xE8\x1F\x14\x00\x00",5,0x450458,&da,DISASM_CODE);
  printf("%3i  %-24s  %-24s   jmpconst=%08X\n",l,da.dump,da.result,da.jmpconst);

  // JNZ 450517
  l=Disasm("\x75\x72",2,0x4504A3,&da,DISASM_CODE);
  printf("%3i  %-24s  %-24s   jmpconst=%08X\n",l,da.dump,da.result,da.jmpconst);

  // 汇编程序的演示
  printf("\n汇编:\n");

  // 汇编上面的命令. 组装上面的命令之一。 首先使用32位尝试
  pasm="ADD [DWORD 475AE0],1";
  printf("%s:\n",pasm);
  j=Assemble(pasm,0x400000,&am,0,0,errtext);
  n=sprintf(s,"%3i  ",j);
  for (i=0; i<j; i++) n+=sprintf(s+n,"%02X ",am.code[i]);
  if (j<=0) sprintf(s+n,"  error=\"%s\"",errtext);
  printf("%s\n",s);

  // 然后变量尝试8位立即数
  j=Assemble(pasm,0x400000,&am,0,2,errtext);
  n=sprintf(s,"%3i  ",j);
  for (i=0; i<j; i++) n+=sprintf(s+n,"%02X ",am.code[i]);
  if (j<=0) sprintf(s+n,"  error=\"%s\"",errtext);
  printf("%s\n",s);

  //错误，无法确定操作数的大小
  pasm="add dword ptr ds:[0x475AE0],0x1";//原来:pasm="MOV [475AE0],20";
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
