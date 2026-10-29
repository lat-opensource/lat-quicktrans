#!/usr/bin/env python3
"""Actual PALIGNR MMX block, modeled vector operations and memory."""
from pathlib import Path
import subprocess,tempfile,os
s=(Path(__file__).resolve().parents[1]/'src/emitter/fast_translator/emit-simd.inc.c').read_text();b=s[s.index('static int ft_emit_palignr_mmx_template'):s.index('static int ft_emit_pshufb_mmx_template')]
h=r'''
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
enum{dt_X86_INS_PALIGNR=1,ft_vscratch=16,la_zero=31};
typedef struct{int modrm_reg,modrm_rm,modrm_mod,imm,id,prefix0,prefix2;}FastTemplateFields;
typedef int TranslationBlock;typedef uint64_t target_ulong;
static unsigned char v[32][16],memory[8];static int loads;
#define ft_mmx(x) (x)
#define T(o) (*(*(o))++=0)
#define FT_LA_MOVGR2FR_D_EMIT(o,d,s) do{memset(v[d],0,8);T(o);}while(0)
#define FT_LA_VINSGR2VR_D_EMIT(o,d,s,k) do{memset(v[d]+8*(k),0,8);T(o);}while(0)
#define FT_LA_FMOV_D_EMIT(o,d,s) do{memmove(v[d],v[s],8);T(o);}while(0)
#define FT_LA_VOR_V_EMIT(o,d,s,t) do{for(int j=0;j<16;j++)v[d][j]=v[s][j]|v[t][j];T(o);}while(0)
#define FT_LA_VEXTRINS_D_EMIT(o,d,s,n) do{unsigned char tmp[8];memcpy(tmp,v[s]+8*((n)&1),8);memcpy(v[d]+8*(((n)>>4)&1),tmp,8);T(o);}while(0)
#define FT_LA_VBSRL_V_EMIT(o,d,s,n) do{unsigned char tmp[16]={0};memcpy(tmp,v[s]+(n),16-(n));memcpy(v[d],tmp,16);T(o);}while(0)
static bool ft_emit_mmxm64_src(uint32_t**o,const FastTemplateFields*f,uint64_t pc,int*src){if(f->modrm_mod==3)*src=f->modrm_rm;else{*src=ft_vscratch;memcpy(v[*src],memory,8);loads++;T(o);}return true;}
'''
t=r'''
int main(void){uint32_t code[32];unsigned cases=0;for(int d=0;d<8;d++)for(int s=0;s<8;s++)for(int mem=0;mem<2;mem++)for(int imm=0;imm<256;imm++){
for(int k=0;k<32;k++)for(int j=0;j<16;j++)v[k][j]=(k*31+j*17+imm)&255;for(int j=0;j<8;j++)memory[j]=j*29+imm;
unsigned char joined[32]={0},orig[8],want[8]={0};memcpy(orig,v[s],8);memcpy(joined,mem?memory:v[s],8);memcpy(joined+8,v[d],8);if(imm<16)memcpy(want,joined+imm,8);
FastTemplateFields f={.modrm_reg=d,.modrm_rm=s,.modrm_mod=mem?0:3,.imm=imm,.id=1};loads=0;int n=ft_emit_palignr_mmx_template(&f,0,0,code);assert(memcmp(v[d],want,8)==0);if(s!=d)assert(memcmp(v[s],orig,8)==0);assert(loads==(mem&&imm<8));assert(n==(imm>=16?1:imm>=8?2:imm==0?1+mem:3+mem));cases++;}
printf("PALIGNR MMX actual emitter: %u cases PASS\n",cases);}
'''
with tempfile.TemporaryDirectory() as d:
 p=Path(d)/'t.c';p.write_text(h+b+t);exe=Path(d)/'t'
 subprocess.run([os.environ.get('CC','cc'),'-O2','-fsanitize=undefined','-fno-sanitize-recover=all',str(p),'-o',str(exe)],check=True);subprocess.run([str(exe)],check=True)
