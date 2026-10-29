#!/usr/bin/env python3
"""Interpret actual stack emitter blocks; memory faults are not modeled."""
from pathlib import Path
import os, subprocess, tempfile
s=(Path(__file__).resolve().parents[1]/'src/emitter/fast_translator/emit-stack.inc.c').read_text()
blocks=s[s.index('    case FT_POP_R64:'):s.index('    case FT_POP_R16:')]
blocks+=s[s.index('    case FT_PUSH_R64:'):s.index('    case FT_PUSH_RM64:')]
pusha=s[s.index('                /* RSP is updated'):s.index('            } else {\n                int regs[8]')]
poprm=s[s.index('            if (width == 32) {\n                FT_LA_LD_WU_EMIT'):s.index('\n        if (!ft_emit_mem_addr',s.index('    case FT_POP_RM64:'))]
poprm=poprm[:poprm.rindex('        }')]
head=r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
enum {FT_POP_R64,FT_PUSH_R64,FT_PUSH_R16,GPR_NUM=16,rsp_index=4,la_t0=16,la_zero=31};
typedef struct {int kind,reg,alu_width;} FastTemplateFields;
static uint64_t r[32];static unsigned char mem[4096];
#define ft_gpr(x) (x)
#define T(o) (*(*(o))++=0)
static uint64_t load(uint64_t a,int n){uint64_t v=0;assert(a+n<=sizeof(mem));memcpy(&v,mem+a,n);return v;}
static void store(uint64_t a,uint64_t v,int n){assert(a+n<=sizeof(mem));memcpy(mem+a,&v,n);}
#define FT_LA_OR_EMIT(o,d,s,t) do{r[d]=r[s]|r[t];T(o);}while(0)
#define FT_LA_ADDI_D_EMIT(o,d,s,k) do{r[d]=r[s]+(k);T(o);}while(0)
#define FT_LA_LD_D_EMIT(o,d,s,k) do{uint64_t a=r[s]+(k);r[d]=load(a,8);T(o);}while(0)
#define FT_LA_LD_WU_EMIT(o,d,s,k) do{uint64_t a=r[s]+(k);r[d]=load(a,4);T(o);}while(0)
#define FT_LA_ST_D_EMIT(o,v,s,k) do{store(r[s]+(k),r[v],8);T(o);}while(0)
#define FT_LA_ST_W_EMIT(o,v,s,k) do{store(r[s]+(k),r[v],4);T(o);}while(0)
#define FT_LA_ST_H_EMIT(o,v,s,k) do{store(r[s]+(k),r[v],2);T(o);}while(0)
'''
body='static int emit(const FastTemplateFields *fields,uint32_t *code){uint32_t*out=code;switch(fields->kind){'+blocks+'}return out-code;}\n'
body+='static int pusha(int width,uint32_t *code){uint32_t*out=code;int step=width/8;int regs[8]={0,1,2,3,4,5,6,7};'+pusha+'return out-code;}\n'
body+='static int poprm(int dst,int width,uint32_t *code){uint32_t*out=code;int bytes=width/8;'+poprm+'}\n'
tail=r'''
int main(void){uint32_t code[64];unsigned cases=0;uint64_t seed=123;
for(int j=0;j<256;j++)for(int reg=0;reg<16;reg++)for(int w=16;w<=64;w*=2){
for(int i=0;i<32;i++){seed^=seed<<13;seed^=seed>>7;seed^=seed<<17;r[i]=seed;}r[31]=0;r[4]=2048;uint64_t value=r[reg],mask=w==64?UINT64_MAX:(1ULL<<w)-1;FastTemplateFields f={w==16?FT_PUSH_R16:FT_PUSH_R64,reg,w};
assert(emit(&f,code)==2);assert(r[4]==2048-w/8&&load(r[4],w/8)==(value&mask));cases++;
if(w!=16){r[4]=2048;store(2048,seed,8);f.kind=FT_POP_R64;assert(emit(&f,code)==(reg==4?1:2));assert(r[reg]==(seed&mask));if(reg!=4)assert(r[4]==2048+w/8);cases++;
if(reg!=4){r[4]=2048;assert(poprm(reg,w,code)==2);assert(r[reg]==(seed&mask)&&r[4]==2048+w/8);cases++;}}
}
for(int w=16;w<=32;w*=2){for(int i=0;i<8;i++)r[i]=0x12340000+i;r[4]=2048;uint64_t saved[8];memcpy(saved,r,sizeof(saved));assert(pusha(w,code)==9);for(int i=0;i<8;i++)assert(load(2048-(i+1)*w/8,w/8)==(saved[i]&((1ULL<<w)-1)));assert(r[4]==2048-8*w/8);cases++;}
printf("stack actual emitter blocks: %u cases PASS (modeled memory)\n",cases);}
'''
with tempfile.TemporaryDirectory() as d:
 p=Path(d)/'test.c';p.write_text(head+body+tail);exe=Path(d)/'test'
 subprocess.run([os.environ.get('CC','cc'),'-std=c99','-O2','-Werror','-fsanitize=undefined','-fno-sanitize-recover=all',str(p),'-o',str(exe)],check=True)
 subprocess.run([str(exe)],check=True)
