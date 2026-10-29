#!/usr/bin/env python3
"""Model actual EXTRACTPS function, including full GPR zero extension."""
from pathlib import Path
import subprocess,tempfile,os
s=(Path(__file__).resolve().parents[1]/'src/emitter/fast_translator/emit-simd.inc.c').read_text();a=s.index('static int ft_emit_extractps_template');b=s.index('\nstatic int ',a+10)
head=r'''
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
enum{XMM_NUM=16,GPR_NUM=16,la_t1=20,dt_X86_PREFIX_OPSIZE=0x66,dt_X86_INS_EXTRACTPS};
typedef struct{int modrm_reg,modrm_rm,modrm_mod,imm,prefix2,id;}FastTemplateFields;
typedef void TranslationBlock;typedef uint64_t target_ulong;
static uint64_t g[32];static uint32_t v[16][4],mem[3];
#define ft_modrm_reg_index(f) ((f)->modrm_reg)
#define ft_modrm_rm_index(f) ((f)->modrm_rm)
#define ft_gpr(x) (x)
#define ft_xmm(x) (x)
#define FT_LA_VPICKVE2GR_WU_EMIT(o,d,s,i) do{g[d]=v[s][i];*(*(o))++=0;}while(0)
static bool ft_emit_store_rm32(uint32_t **o,const FastTemplateFields*f,target_ulong pc,int src,bool zero){(void)pc;assert(f->modrm_mod!=3&&!zero);mem[1]=g[src];*(*o)++=0;return true;}
'''
tail=r'''
int main(void){unsigned cases=0;uint32_t code[8];for(int src=0;src<16;src++)for(int dst=0;dst<16;dst++)for(int m=0;m<2;m++)for(int imm=0;imm<256;imm++){
for(int r=0;r<32;r++)g[r]=UINT64_MAX-r;for(int r=0;r<16;r++)for(int j=0;j<4;j++)v[r][j]=0x80000000U+(r*1111+j*313+imm);
uint64_t old[32];memcpy(old,g,sizeof g);mem[0]=0x12345678;mem[1]=0;mem[2]=0xfedcba98;FastTemplateFields f={src,dst,m?0:3,imm,0x66,dt_X86_INS_EXTRACTPS};int n=ft_emit_extractps_template(&f,0,0,code);uint64_t want=v[src][imm&3];assert(n==1+m);if(m)assert(mem[1]==want);else old[dst]=want;assert(!memcmp(old,g,16*sizeof(uint64_t)));assert(mem[0]==0x12345678&&mem[2]==0xfedcba98);cases++;}printf("EXTRACTPS actual function: %u cases PASS\n",cases);}
'''
with tempfile.TemporaryDirectory() as d:
 p=Path(d)/'t.c';p.write_text(head+s[a:b]+tail);exe=Path(d)/'t';subprocess.run([os.environ.get('CC','cc'),'-O2','-fsanitize=undefined','-fno-sanitize-recover=all',str(p),'-o',str(exe)],check=True);subprocess.run([str(exe)],check=True)
