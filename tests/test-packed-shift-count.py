#!/usr/bin/env python3
"""Model actual variable-count emission blocks; no guest/performance claims."""
from pathlib import Path
import os, subprocess, tempfile
root = Path(__file__).resolve().parents[1]
s = (root/'src/emitter/fast_translator/emit-template.inc.c').read_text()
a = s.index('            int mmx_dst = ft_modrm_reg_index(fields);', s.index('fields->opcode1 == 0xd1'))
b = s.index('            goto simd_bin_done;', a)
mmx = s[a:b]
assert 'int mask = ft_vscratch + 3;' in mmx
assert 'count_src' not in mmx
# The source/address setup is tested by passing either a guest register or scratch.
a = mmx.index('            FT_LA_VREPLVEI_D_EMIT')
mmx = '''int mmx_dst=dst, mask=ft_vscratch+3, count=ft_vscratch+1;
bool is_left=kind<3, is_word=kind%3==0, is_dword=kind%3==1;\n''' + mmx[a:]
a = s.index('            /* Keep the mask separate', s.index('if (id == dt_X86_INS_PSLLW'))
b = s.index('            goto simd_bin_done;', a)
xmm = s[a:b]
s = (root/'src/emitter/fast_translator/emit-simd.inc.c').read_text()
a = s.index('static int ft_emit_psra_mmx_template')
b = s.index('\nstatic int ', a+10)
mmxa = s[a:b]; mmxa = '''int valid_count=ft_vscratch+3, count=ft_vscratch+1, sign=ft_vscratch+2;
bool is_psrad=kind==7;\n''' + mmxa[mmxa.index('    FT_LA_VREPLVEI_D_EMIT'):mmxa.index('    return (out - code);')]
# Assert the real declarations used by the extracted blocks, including alias protection.
assert 'int valid_count = ft_vscratch + 3;' in s[a:b]
assert 'count_src' not in s[a:b]
head = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
enum {ft_vscratch=24, dt_X86_INS_PSLLW, dt_X86_INS_PSLLD, dt_X86_INS_PSLLQ,
 dt_X86_INS_PSRLW, dt_X86_INS_PSRLD, dt_X86_INS_PSRLQ, dt_X86_INS_PSRAW, dt_X86_INS_PSRAD};
enum {FT_LA_OPCODE_VREPLVEI_H=1<<20, FT_LA_OPCODE_VREPLVEI_W=2<<20, FT_LA_OPCODE_VREPLVEI_D=3<<20,
 FT_LA_OPCODE_VSLL_H=4<<20, FT_LA_OPCODE_VSLL_W=5<<20, FT_LA_OPCODE_VSLL_D=6<<20,
 FT_LA_OPCODE_VSRL_H=7<<20, FT_LA_OPCODE_VSRL_W=8<<20, FT_LA_OPCODE_VSRL_D=9<<20,
 FT_LA_OPCODE_VSRA_H=10<<20, FT_LA_OPCODE_VSRA_W=11<<20,
 FT_LA_OPCODE_VSRAI_H=12<<20, FT_LA_OPCODE_VSRAI_W=13<<20};
static uint64_t v[32][2];
#define ft_xmm(x) (x)
#define ft_mmx(x) (x)
static uint64_t lane(int r,int w,int i){return (v[r][i*w/64]>>(i*w%64)) & (UINT64_MAX>>(64-w));}
static uint64_t ash(uint64_t x,int w,unsigned n){uint64_t m=UINT64_MAX>>(64-w);n%=w;return (x>>n)|((n&&(x>>(w-1)))?(m^(m>>n)):0);}
static void op(uint32_t **out,int opcode,int d,int s,int t,int imm){uint64_t z[2]={0};int w=0,mode=0;
 if(opcode<=3){w=opcode==1?16:opcode==2?32:64;uint64_t x=lane(s,w,0);for(int i=0;i<128/w;i++)z[i*w/64]|=x<<(i*w%64);}
 else if(opcode<=13){if(opcode<=6){w=16<<(opcode-4);mode=0;}else if(opcode<=9){w=16<<(opcode-7);mode=1;}else{w=(opcode==10||opcode==12)?16:32;mode=2;}
 for(int i=0;i<128/w;i++){uint64_t x=lane(s,w,i);unsigned n=(opcode>=12?imm:lane(t,w,i))%(unsigned)w;uint64_t y=mode==0?x<<n:mode==1?x>>n:ash(x,w,n);z[i*w/64]|=(y&(UINT64_MAX>>(64-w)))<<(i*w%64);}}
 else for(int i=0;i<2;i++){switch(opcode){case 14:z[i]=v[s][i]<=(uint64_t)imm?UINT64_MAX:0;break;case 15:z[i]=v[s][i]>>imm;break;case 16:z[i]=v[s][i]==(uint64_t)imm?UINT64_MAX:0;break;case 17:z[i]=v[s][i]&v[t][i];break;case 18:z[i]=(v[s][i]&~v[imm][i])|(v[t][i]&v[imm][i]);break;}}
 memcpy(v[d],z,16);*(*out)++=0;}
#define FT_LA_VREPLVEI_D_EMIT(o,d,s,i) op(o,3,d,s,0,i)
#define FT_LA_VREPLVEI_H_EMIT(o,d,s,i) op(o,1,d,s,0,i)
#define FT_LA_VREPLVEI_W_EMIT(o,d,s,i) op(o,2,d,s,0,i)
#define FT_LA_VSLEI_DU_EMIT(o,d,s,i) op(o,14,d,s,0,i)
#define FT_LA_VSRLI_D_EMIT(o,d,s,i) op(o,15,d,s,0,i)
#define FT_LA_VSEQI_D_EMIT(o,d,s,i) op(o,16,d,s,0,i)
#define FT_LA_VAND_V_EMIT(o,d,s,t) op(o,17,d,s,t,0)
#define FT_LA_VBITSEL_V_EMIT(o,d,s,t,m) op(o,18,d,s,t,m)
#define FT_LA_VSRAI_H_EMIT(o,d,s,i) op(o,12,d,s,0,i)
#define FT_LA_VSRAI_W_EMIT(o,d,s,i) op(o,13,d,s,0,i)
#define FT_LA_VSRA_H_EMIT(o,d,s,t) op(o,10,d,s,t,0)
#define FT_LA_VSRA_W_EMIT(o,d,s,t) op(o,11,d,s,t,0)
static uint32_t ft_gpr3(uint32_t op,int d,int s,int t){return op|d|(s<<5)|(t<<10);}
static void ft_emit_raw(uint32_t **o,uint32_t x){int code=x>>20;op(o,code,x&31,(x>>5)&31,(x>>10)&31,(x>>10)&31);}
'''
body = 'static int emit(int family,int kind,int dst,int src,uint32_t*code){uint32_t*out=code;int id=dt_X86_INS_PSLLW+kind;uint32_t la_opcode=(kind+4)<<20; if(family==0){'+xmm+'}else if(kind<6){'+mmx+'}else{'+mmxa+'}return out-code;}\n'
tail = r'''
int main(void){uint32_t code[32];unsigned cases=0;uint64_t counts[]={0,1,14,15,16,17,30,31,32,33,62,63,64,65,255,256,65535,65536,0xffffffff,0x100000000,0x8000000000000000ULL,UINT64_MAX};
for(int family=0;family<2;family++)for(int kind=0;kind<8;kind++)for(int dst=0;dst<(family?8:16);dst++)for(int si=0;si<=(family?8:16);si++)for(unsigned c=0;c<sizeof(counts)/sizeof(counts[0]);c++){
int src=si==(family?8:16)?ft_vscratch:si;for(int r=0;r<32;r++){v[r][0]=0x8123456789abcdefULL^((uint64_t)r*0x101010101010101ULL);v[r][1]=~v[r][0];}v[src][0]=counts[c];
uint64_t before[2],source[2],want[2]={0};memcpy(before,v[dst],16);memcpy(source,v[src],16);int w=kind<6?16<<(kind%3):kind==6?16:32;
for(int i=0;i<(family?64:128)/w;i++){uint64_t x=lane(dst,w,i),y,n=counts[c];if(kind>=6)y=ash(x,w,n>=(unsigned)w?w-1:n);else if(n>=(unsigned)w)y=0;else y=kind<3?x<<n:x>>n;want[i*w/64]|=(y&(UINT64_MAX>>(64-w)))<<(i*w%64);}
int n=emit(family,kind,dst,src,code);assert(n==(kind>=6?6:kind%3==2?6:5));assert(memcmp(v[dst],want,family?8:16)==0);if(src!=dst)assert(memcmp(v[src],source,16)==0);cases++;}
printf("variable packed shifts: %u cases PASS\n",cases);}
'''
with tempfile.TemporaryDirectory() as d:
 p=Path(d)/'t.c';p.write_text(head+body+tail); exe=Path(d)/'t'
 subprocess.run([os.environ.get('CC','cc'),'-O2','-fsanitize=undefined','-fno-sanitize-recover=all',str(p),'-o',str(exe)],check=True)
 subprocess.run([str(exe)],check=True)
