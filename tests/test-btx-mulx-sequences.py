#!/usr/bin/env python3
"""Interpret actual BT-register/MULX emitters; address/load interfaces are modeled."""
import os
import subprocess
import tempfile
from pathlib import Path
root = Path(__file__).resolve().parents[1]
s = (root / 'src/emitter/fast_translator/emit-bit.inc.c').read_text()
def section(a, b=None):
    return s[s.index(a):s.index(b) if b else len(s)]
body = section('static int ft_emit_mulx_template', 'static void ft_bls_set_cf_from_nonzero')
body += section('static void ft_emit_btx_cf', 'static bool ft_emit_locked_btx')
body += section('static int ft_emit_btx_reg_template')
ops = ['OR','BSTRPICK_D','MUL_D','MULH_DU','MUL_W','MULH_WU','SRL_D','SRL_W','ANDI','X86MTFLAG','SLLI_D','SRAI_D','ALSL_D','ORI','NOR','AND','XOR','ANDN']
head = r'''
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
enum {GPR_NUM=16,rdx_index=2,la_t0=16,la_t1,la_t2,la_t3,la_t4,la_zero=31};
enum {FT_MULX_R64_R_RM=1,FT_MULX_R32_R_RM,dt_X86_INS_BT,dt_X86_INS_BTS,dt_X86_INS_BTR,dt_X86_INS_BTC,dt_X86_PREFIX_OPSIZE,dt_X86_PREFIX_LOCK};
enum {FT_LA_OPCODE_LD_D=50,FT_LA_OPCODE_LD_HU,FT_LA_OPCODE_LD_WU,FT_LA_OPCODE_ST_D,FT_LA_OPCODE_ST_H,FT_LA_OPCODE_ST_W,FT_LA_OPCODE_SLL_D,FT_LA_OPCODE_SLL_W,LOAD=60};
typedef struct {int kind,reg,imm,src,modrm_mod,prefix2,prefix0,id,addr; bool rex,skip_flags;} FastTemplateFields;
typedef int TranslationBlock; typedef uint64_t target_ulong;
typedef struct {int op,d,s,t,k;} Ins;
static Ins ins[128]; static int n; static uint64_t r[32],mem,flags,access,stored;static int stores;
static uint32_t add(int op,int d,int s,int t,int k){ins[n]=(Ins){op,d,s,t,k};return n++;}
#define ft_gpr(x) (x)
#define ft_rex_w(f) ((f)->rex)
#define ft_modrm_reg_index(f) ((f)->reg)
#define ft_modrm_rm_index(f) ((f)->src)
#define E(o,op,d,s,t,k) (*(*(o))++=add(op,d,s,t,k))
static void ft_emit_raw(uint32_t **o,uint32_t v){*(*o)++=v;}
static uint32_t ft_gpr3(int op,int d,int s,int t){return add(op,d,s,t,0);}
static uint32_t ft_gpr3_imm12(int op,int d,int s,int k){return add(op,d,s,0,k);}
static bool load(uint32_t **o,const FastTemplateFields*f,int*src,int w){if(f->modrm_mod==3)*src=f->src;else{E(o,LOAD,la_t0,0,0,w);*src=la_t0;}return true;}
#define ft_emit_load_rm64(o,f,p,s) load(o,f,s,64)
#define ft_emit_load_rm32(o,f,p,s) load(o,f,s,32)
static bool ft_emit_rip_or_mem_addr(uint32_t **o,const FastTemplateFields*f,target_ulong pc,int*addr){*addr=f->addr;return true;}
static int ft_mem_access_offset(const FastTemplateFields*f,int addr){return 13;}
static bool ft_emit_locked_btx(uint32_t**o,const FastTemplateFields*f,target_ulong pc,int ext,int width,bool reg,int val){assert(0);return false;}
'''
for i, op in enumerate(ops, 1):
    if op == 'X86MTFLAG':
        head += f'#define FT_LA_{op}_EMIT(o,s,k) E(o,{i},0,s,0,k)\n'
    elif op in ('BSTRPICK_D','ALSL_D'):
        head += f'#define FT_LA_{op}_EMIT(o,d,s,t,k) E(o,{i},d,s,t,k)\n'
    else:
        head += f'#define FT_LA_{op}_EMIT(o,d,s,t) E(o,{i},d,s,t,0)\n'
tail = r'''
static void run(uint32_t*c,int len){for(int j=0;j<len;j++){Ins x=ins[c[j]];uint64_t a=r[x.s],b=(x.t>=0&&x.t<32)?r[x.t]:0;switch(x.op){
case 1:r[x.d]=a|b;break;
case 2:r[x.d]=(a>>x.k)&(UINT64_MAX>>(63-(x.t-x.k)));break;
case 3:r[x.d]=a*b;break;
case 4:r[x.d]=(uint64_t)(((__uint128_t)a*b)>>64);break;
case 5:r[x.d]=(uint64_t)(int64_t)(int32_t)((uint32_t)a*(uint32_t)b);break;
case 6:r[x.d]=(uint64_t)(int64_t)(int32_t)(((uint64_t)(uint32_t)a*(uint32_t)b)>>32);break;
case 7:r[x.d]=a>>(b&63);break;
case 8:r[x.d]=(uint64_t)(int64_t)(int32_t)((uint32_t)a>>(b&31));break;
case 9:r[x.d]=a&x.t;break;
case 10:flags=(flags&~(uint64_t)x.k)|(a&x.k);break;
case 11:r[x.d]=a<<x.t;break;
case 12:r[x.d]=(uint64_t)((int64_t)a>>x.t);break;
case 13:r[x.d]=(a<<(x.k+1))+b;break;
case 14:r[x.d]=a|x.t;break;
case 15:r[x.d]=~(a|b);break;
case 16:r[x.d]=a&b;break;
case 17:r[x.d]=a^b;break;
case 18:r[x.d]=a&~b;break;
case FT_LA_OPCODE_LD_D:case FT_LA_OPCODE_LD_HU:case FT_LA_OPCODE_LD_WU:access=a+x.k;r[x.d]=x.op==50?mem:x.op==51?(uint16_t)mem:(uint32_t)mem;break;
case FT_LA_OPCODE_ST_D:case FT_LA_OPCODE_ST_H:case FT_LA_OPCODE_ST_W:assert(a+x.k==access);stored=x.op==53?r[x.d]:x.op==54?(uint16_t)r[x.d]:(uint32_t)r[x.d];stores++;break;
case FT_LA_OPCODE_SLL_D:r[x.d]=a<<(b&63);break;
case FT_LA_OPCODE_SLL_W:r[x.d]=(uint64_t)(int64_t)(int32_t)((uint32_t)a<<(b&31));break;
case LOAD:r[x.d]=x.k==64?mem:(uint64_t)(int64_t)(int32_t)mem;break;
default:assert(0);}}}
static uint64_t seed=0x123abc987ULL;
static uint64_t rnd(void){seed^=seed<<13;seed^=seed>>7;seed^=seed<<17;return seed;}
int main(void){unsigned mulcases=0,btcases=0;uint32_t code[128];
for(int w=32;w<=64;w+=32)for(int memory=0;memory<2;memory++)for(int hi=0;hi<16;hi++)for(int lo=0;lo<16;lo++)for(int src=0;src<16;src++)for(int j=0;j<8;j++){
for(int k=0;k<32;k++)r[k]=j==0?0:j==1?UINT64_MAX:rnd();r[31]=0;mem=j==0?0:j==1?UINT64_MAX:rnd();
uint64_t a=memory?mem:r[src],b=r[2],initial[32];memcpy(initial,r,sizeof r);if(w==32){a=(uint32_t)a;b=(uint32_t)b;}
__uint128_t product=(__uint128_t)a*b;uint64_t low=w==64?(uint64_t)product:(uint32_t)product,high=w==64?(uint64_t)(product>>64):(uint32_t)(product>>32);
FastTemplateFields f={.kind=w==64?FT_MULX_R64_R_RM:FT_MULX_R32_R_RM,.reg=hi,.imm=lo,.src=src,.modrm_mod=memory?0:3,.rex=w==64};
n=0;int count=ft_emit_mulx_template(&f,0,0,code);int sr=memory?la_t0:src;int expected=memory+(w==32?4:(lo==hi|| (lo!=sr&&lo!=2)?2:3));assert(count==expected);flags=0x8d5;run(code,count);assert(r[hi]==high);if(lo!=hi)assert(r[lo]==low);for(int k=0;k<16;k++)if(k!=hi&&k!=lo)assert(r[k]==initial[k]);assert(flags==0x8d5);mulcases++;
}
int64_t indexes[]={-1025,-65,-64,-33,-32,-17,-16,-1,0,1,15,16,31,32,63,64,1025};
for(int w=16;w<=64;w*=2)for(int op=0;op<4;op++)for(int dead=0;dead<2;dead++)for(int ai=0;ai<5;ai++)for(unsigned j=0;j<sizeof(indexes)/sizeof(*indexes);j++){
int addresses[]={5,la_t0,la_t1,la_t2,la_t3};int addr=addresses[ai];for(int k=0;k<32;k++)r[k]=rnd();r[31]=0;r[8]=(uint64_t)indexes[j];r[addr]=0x100000;mem=rnd();flags=0x8d5;stores=0;stored=0;
FastTemplateFields f={.reg=8,.id=dt_X86_INS_BT+op,.prefix2=w==16?dt_X86_PREFIX_OPSIZE:0,.rex=w==64,.skip_flags=dead,.addr=addr};
uint64_t value=w==64?mem:w==32?(uint32_t)mem:(uint16_t)mem;int bit=(uint64_t)indexes[j]&(w-1);uint64_t mask=1ULL<<bit;uint64_t want=op==0?value:op==1?value|mask:op==2?value&~mask:value^mask;
n=0;int count=ft_emit_btx_reg_template(&f,0,0,code);int fused=0;for(int k=0;k<count;k++)if(ins[k].op==13)fused++;assert(fused==1);run(code,count);int64_t word=indexes[j]>=0?indexes[j]/w:-((-indexes[j]+w-1)/w);assert(access==0x100000+13+word*(w/8));assert(stores==(op!=0));if(op)assert(stored==want);assert(flags==(dead?0x8d5:(0x8d4|((value>>bit)&1))));btcases++;
}

for(int w=16;w<=64;w*=2)for(int op=0;op<4;op++)for(int dead=0;dead<2;dead++)for(int dst=0;dst<16;dst++)for(int idx=0;idx<16;idx++)for(int j=0;j<8;j++){
for(int k=0;k<32;k++)r[k]=rnd();r[31]=0;if(j==0)r[dst]=0;if(j==1)r[dst]=UINT64_MAX;
uint64_t value=r[dst],index=r[idx],initial[32];memcpy(initial,r,sizeof r);int bit=index&(w-1);uint64_t mask=1ULL<<bit;
uint64_t want=op==0?value:op==1?value|mask:op==2?value&~mask:value^mask;if(w==32&&op)want=(uint32_t)want;
FastTemplateFields f={.reg=idx,.src=dst,.modrm_mod=3,.id=dt_X86_INS_BT+op,.prefix2=w==16?dt_X86_PREFIX_OPSIZE:0,.rex=w==64,.skip_flags=dead};
flags=0x8d5;n=0;int count=ft_emit_btx_reg_template(&f,0,0,code);assert(count>0);run(code,count);assert(r[dst]==want);for(int k=0;k<16;k++)if(k!=dst)assert(r[k]==initial[k]);assert(flags==(dead?0x8d5:(0x8d4|((value>>bit)&1))));btcases++;
}
printf("MULX %u cases; BT/BTS/BTR/BTC register+memory %u cases PASS (modeled memory interface)\n",mulcases,btcases);
}
'''
with tempfile.TemporaryDirectory() as d:
    c=Path(d)/'sequences.c';c.write_text(head+body+tail)
    exe=Path(d)/'sequences'
    subprocess.run([os.environ.get('CC','cc'),'-std=c99','-O2','-Werror','-fsanitize=undefined','-fno-sanitize-recover=all',str(c),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True)
