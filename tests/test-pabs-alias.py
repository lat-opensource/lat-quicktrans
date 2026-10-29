#!/usr/bin/env python3
"""Interpret the actual XMM PABS emission block, including source aliases."""
import os, subprocess, tempfile
from pathlib import Path
s=(Path(__file__).resolve().parents[1]/'src/emitter/fast_translator/emit-template.inc.c').read_text()
a=s.index('            /* A separate zero preserves');b=s.index('            goto simd_bin_done;',a);body=s[a:b]
head=r'''
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
enum {ft_vscratch=24};
static uint32_t v[32][4];
#define ft_xmm(x) (x)
#define FT_LA_VANDI_B_EMIT(o,d,s,n) do {assert(n==0);memset(v[d],0,16);*(*(o))++=0;}while(0)
static uint32_t ft_gpr3(int op,int d,int s,int t){return (op<<20)|d|(s<<5)|(t<<10);}
static void ft_emit_raw(uint32_t **o,uint32_t ins){int w=ins>>20,d=ins&31,s=(ins>>5)&31,t=(ins>>10)&31;uint32_t z[4]={0};
for(int i=0;i<128/w;i++){uint64_t mask=(1ULL<<w)-1;uint64_t x=(v[s][i*w/32]>>(i*w%32))&mask;assert(v[t][i*w/32]==0);uint64_t y=(x>>(w-1))?(-x)&mask:x;z[i*w/32]|=(uint32_t)y<<(i*w%32);}memcpy(v[d],z,16);*(*o)++=0;}
'''
tail=r'''
int main(void){unsigned cases=0;uint32_t code[8];uint32_t edges[]={0,1,0xffffffff,0x80808080,0x80008000,0x80000000,0x7f7f7f7f,0x7fff7fff,0x7fffffff};
for(int w=8;w<=32;w*=2)for(int dst=0;dst<16;dst++)for(int si=0;si<17;si++)for(int c=0;c<256;c++){
int src=si==16?24:si;for(int r=0;r<32;r++)for(int j=0;j<4;j++)v[r][j]=c<9?edges[c]:(uint32_t)(0x9e3779b9U*(c*67+r*11+j));
uint32_t want[4]={0},orig[4];memcpy(orig,v[src],16);for(int i=0;i<128/w;i++){uint64_t mask=(1ULL<<w)-1;int64_t x=(orig[i*w/32]>>(i*w%32))&mask;if(x&(1LL<<(w-1)))x-=1LL<<w;uint64_t y=x<0?-x:x;want[i*w/32]|=(uint32_t)y<<(i*w%32);}
assert(emit(w,dst,src,code)==2);assert(!memcmp(want,v[dst],16));if(src!=dst)assert(!memcmp(orig,v[src],16));cases++;}printf("PABS actual block: %u cases PASS\n",cases);}
'''
with tempfile.TemporaryDirectory() as d:
 p=Path(d)/'test.c';p.write_text(head+'static int emit(int la_opcode,int dst,int src,uint32_t*code){uint32_t*out=code;'+body+'return out-code;}\n'+tail)
 exe=Path(d)/'test';subprocess.run([os.environ.get('CC','cc'),'-O2','-fsanitize=undefined','-fno-sanitize-recover=all',str(p),'-o',str(exe)],check=True);subprocess.run([str(exe)],check=True)
