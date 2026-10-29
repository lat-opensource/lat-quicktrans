#!/usr/bin/env python3
"""Check actual MMX PEXTRW/PINSRW emitters with register/load models."""
from pathlib import Path
import subprocess,tempfile,os
s=(Path(__file__).resolve().parents[1]/'src/emitter/fast_translator/emit-simd.inc.c').read_text()
blocks=[]
for name in ['ft_emit_pextrw_r32_mmx_imm8_template','ft_emit_pinsrw_mmx_rm16_imm8_template']:
 a=s.index('static int '+name);b=s.index('\nstatic int ',a+10);blocks.append(s[a:b])
head=r'''
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <stdbool.h>
#include <string.h>
enum {dt_X86_INS_PEXTRW,dt_X86_INS_PINSRW,GPR_NUM=16,la_t0=20};
typedef struct{int id,prefix0,prefix2,modrm_mod,modrm_reg,modrm_rm,imm;}FastTemplateFields;
typedef void TranslationBlock;typedef uint64_t target_ulong;
static uint64_t g[32],v[8][2],mem;static int loads;
#define ft_modrm_reg_index(f) ((f)->modrm_reg)
#define ft_modrm_rm_index(f) ((f)->modrm_rm)
#define ft_gpr(x) (x)
#define ft_mmx(x) (x)
#define FT_LA_VPICKVE2GR_HU_EMIT(o,d,s,i) do{g[d]=(v[s][0]>>((i)*16))&65535;*(*(o))++=0;}while(0)
#define FT_LA_VINSGR2VR_H_EMIT(o,d,s,i) do{uint64_t m=65535ULL<<((i)*16);v[d][0]=(v[d][0]&~m)|((g[s]&65535)<<((i)*16));*(*(o))++=0;}while(0)
static bool ft_emit_load_rm16(uint32_t**o,const FastTemplateFields*f,target_ulong pc,int*src){(void)pc;if(f->modrm_mod==3)*src=f->modrm_rm;else{*src=la_t0;g[*src]=mem&65535;loads++;*(*o)++=0;}return true;}
'''
tail=r'''
int main(void){unsigned cases=0;uint32_t code[8];for(int op=0;op<2;op++)for(int m=0;m<(op?2:1);m++)for(int vr=0;vr<8;vr++)for(int gr=0;gr<16;gr++)for(int imm=0;imm<256;imm++){
for(int r=0;r<32;r++)g[r]=0xfedcba9876543210ULL^(r*0x1000100010001ULL+imm);for(int r=0;r<8;r++){v[r][0]=0x80ff7fff0001ffffULL^(r*0x1000100010001ULL+imm);v[r][1]=0xdeadbeef12345678ULL;}mem=0x123456788001abcdULL+imm;loads=0;
uint64_t oldg[32],oldv[8][2];memcpy(oldg,g,sizeof g);memcpy(oldv,v,sizeof v);
FastTemplateFields f={op?dt_X86_INS_PINSRW:dt_X86_INS_PEXTRW,0,0,m?0:3,op?vr:gr,op?gr:vr,imm};
int n=op?ft_emit_pinsrw_mmx_rm16_imm8_template(&f,0,0,code):ft_emit_pextrw_r32_mmx_imm8_template(&f,0,0,code);
assert(n==1+m&&loads==m);if(op){uint64_t mask=65535ULL<<((imm&3)*16),value=m?mem:oldg[gr];oldv[vr][0]=(oldv[vr][0]&~mask)|((value&65535)<<((imm&3)*16));}else oldg[gr]=(oldv[vr][0]>>((imm&3)*16))&65535;
assert(!memcmp(v,oldv,sizeof v));assert(!memcmp(g,oldg,16*sizeof(uint64_t)));cases++;}printf("MMX element actual functions: %u cases PASS\n",cases);}
'''
with tempfile.TemporaryDirectory() as d:
 p=Path(d)/'t.c';p.write_text(head+'\n'.join(blocks)+tail);exe=Path(d)/'t';subprocess.run([os.environ.get('CC','cc'),'-O2','-fsanitize=undefined','-fno-sanitize-recover=all',str(p),'-o',str(exe)],check=True);subprocess.run([str(exe)],check=True)
