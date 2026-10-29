#!/usr/bin/env python3
"""Interpret actual PSHUFHW/LW block; loads modeled separately from shuffle."""
import subprocess,tempfile,os
from pathlib import Path
s=(Path(__file__).resolve().parents[1]/'src/emitter/fast_translator/emit-template.inc.c').read_text();a=s.index('            int keep = ft_vscratch + 1;');b=s.index('            break;',a);body=s[a:b]
head=r'''
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
enum{ft_vscratch=16,dt_X86_INS_PSHUFLW,dt_X86_INS_PSHUFHW};
typedef struct{int id;}FastTemplateFields;
static uint16_t v[32][8];
#define ft_xmm(x) (x)
#define T(o) (*(*(o))++=0)
#define FT_LA_VOR_V_EMIT(o,d,s,t) do{for(int k=0;k<8;k++)v[d][k]=v[s][k]|v[t][k];T(o);}while(0)
#define FT_LA_VBSRL_V_EMIT(o,d,s,n) do{uint16_t tmp[8]={0};memcpy(tmp,v[s]+(n)/2,16-(n));memcpy(v[d],tmp,16);T(o);}while(0)
#define FT_LA_VSHUF4I_H_EMIT(o,d,s,n) do{uint16_t tmp[8];for(int k=0;k<8;k++)tmp[k]=v[s][(k&4)+(((n)>>((k&3)*2))&3)];memcpy(v[d],tmp,16);T(o);}while(0)
#define FT_LA_VEXTRINS_D_EMIT(o,d,s,n) do{uint16_t tmp[4];memcpy(tmp,v[s]+((n)&1)*4,8);memcpy(v[d]+(((n)>>4)&1)*4,tmp,8);T(o);}while(0)
'''
tail=r'''
int main(void){uint32_t code[16];unsigned cases=0;for(int kind=0;kind<2;kind++)for(int dst=0;dst<16;dst++)for(int src=0;src<=16;src++)for(int imm=0;imm<256;imm++){
for(int r=0;r<32;r++)for(int j=0;j<8;j++)v[r][j]=(r*1009+j*5101+imm*19)&65535;
uint16_t want[8],orig[8];memcpy(orig,v[src],16);memcpy(want,orig,16);for(int k=0;k<4;k++){int base=kind?4:0;want[base+k]=orig[base+((imm>>(k*2))&3)];}
FastTemplateFields f={kind?dt_X86_INS_PSHUFHW:dt_X86_INS_PSHUFLW};int n=emit(&f,dst,src,imm,code);assert(n==(kind?3:4)&&memcmp(v[dst],want,16)==0);if(src!=dst)assert(memcmp(v[src],orig,16)==0);cases++;}
printf("PSHUFHW/LW actual block: %u cases PASS\n",cases);}
'''
with tempfile.TemporaryDirectory() as d:
 p=Path(d)/'t.c';p.write_text(head+'static int emit(const FastTemplateFields*fields,int dst,int src,int imm,uint32_t*code){uint32_t*out=code;'+body+'return out-code;}\n'+tail);exe=Path(d)/'t'
 subprocess.run([os.environ.get('CC','cc'),'-O2','-fsanitize=undefined','-fno-sanitize-recover=all',str(p),'-o',str(exe)],check=True);subprocess.run([str(exe)],check=True)
