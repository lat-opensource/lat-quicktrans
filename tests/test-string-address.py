#!/usr/bin/env python3
"""Execute actual string body emission under three macro configurations."""
import os, subprocess, tempfile
from pathlib import Path
root=Path(__file__).resolve().parents[1]
s=(root/'src/emitter/fast_translator/emit-string.inc.c').read_text()
helpers=s[s.index('static bool ft_string_is_movs'):s.index('static bool ft_emit_string_step')]
body=s[s.index('static bool ft_emit_string_body'):s.index('static int ft_emit_string_template')]
ids=['MOVSB','MOVSW','MOVSD','MOVSQ','STOSB','STOSW','STOSD','STOSQ','LODSB','LODSW','LODSD','LODSQ','CMPSB','CMPSW','CMPSD','CMPSQ','SCASB','SCASW','SCASD','SCASQ']
header=r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
enum {es_index,cs_index,ss_index,ds_index,fs_index,gs_index};
enum {rax_index=0,rsi_index=6,rdi_index=7,la_t0=12,la_t1=13,la_t2=14,la_t3=15,la_t4=16,la_zero=31};
enum {HF_CS64_MASK=128, FT_LA_OPCODE_LD_D=1, FT_LA_OPCODE_X86SUB_B,FT_LA_OPCODE_X86SUB_H,FT_LA_OPCODE_X86SUB_W,FT_LA_OPCODE_X86SUB_D};
typedef struct {struct {uint64_t base;} segs[6];} CPUX86State;
typedef struct {int id,segment,address;bool addr32,skip_flags;} FastTemplateFields;
typedef struct {unsigned flags;} TranslationBlock;
static CPUX86State env;static uint64_t r[32];static unsigned char mem[4096];
static uint64_t sub0,sub1;static int subop;
#define ft_gpr(i) (i)
#define ft_fits_simm12(x) ((x)>=-2048 && (x)<=2047)
static void ft_emit_load_env(uint32_t **o,int d,int off,int op){(void)op;memcpy(&r[d],(char*)&env+off,8);(*o)++;}
static void load(uint32_t **o,int d,int a,int i,int n){assert(r[a]+i+n<=sizeof(mem));r[d]=0;memcpy(&r[d],mem+r[a]+i,n);(*o)++;}
static void store(uint32_t **o,int d,int a,int i,int n){assert(r[a]+i+n<=sizeof(mem));memcpy(mem+r[a]+i,&r[d],n);(*o)++;}
#define FT_LA_BSTRPICK_D_EMIT(o,d,s,h,l) do {r[d]=(r[s]>>(l))&((UINT64_C(1)<<((h)-(l)+1))-1);(*o)++;} while(0)
#define FT_LA_BSTRINS_D_EMIT(o,d,s,h,l) do {uint64_t mask=((UINT64_C(1)<<((h)-(l)+1))-1)<<(l);r[d]=(r[d]&~mask)|((r[s]<<(l))&mask);(*o)++;}while(0)
#define FT_LA_OR_EMIT(o,d,s,z) do {r[d]=r[s]|r[z];(*o)++;} while(0)
#define FT_LA_XOR_EMIT(o,d,s,z) do {r[d]=r[s]^r[z];(*o)++;} while(0)
#define FT_LA_ADD_D_EMIT(o,d,s,t) do {r[d]=r[s]+r[t];(*o)++;} while(0)
#define FT_LA_SLLI_D_EMIT(o,d,s,i) do {r[d]=r[s]<<(i);(*o)++;}while(0)
#define FT_LA_LD_BU_EMIT(o,d,a,i) load(o,d,a,i,1)
#define FT_LA_LD_HU_EMIT(o,d,a,i) load(o,d,a,i,2)
#define FT_LA_LD_WU_EMIT(o,d,a,i) load(o,d,a,i,4)
#define FT_LA_LD_D_EMIT(o,d,a,i) load(o,d,a,i,8)
#define FT_LA_ST_H_EMIT(o,d,a,i) store(o,d,a,i,2)
#define FT_LA_ST_W_EMIT(o,d,a,i) store(o,d,a,i,4)
#define FT_LA_ST_D_EMIT(o,d,a,i) store(o,d,a,i,8)
static bool ft_emit_store_addr_bytes(uint32_t **o,int pc,int a,int off,int d,int n){(void)pc;store(o,d,a,off,n);return true;}
static int ft_gpr2(int op,int a,int b){subop=op;sub0=r[a];sub1=r[b];return op;}
static void ft_emit_raw(uint32_t **o,int op){(void)op;(*o)++;}
"""
header+='enum {'+','.join('dt_X86_INS_'+x for x in ids)+'};\n'
main=r"""
int main(void){unsigned n=0;
 int targets[]={dt_X86_INS_MOVSW,dt_X86_INS_MOVSD,dt_X86_INS_LODSQ,dt_X86_INS_STOSQ,dt_X86_INS_CMPSQ,dt_X86_INS_SCASQ};
 for(int k=0;k<6;k++)for(int mode=0;mode<2;mode++)for(int a32=0;a32<2;a32++)for(int seg=-1;seg<6;seg++)for(int nulltb=0;nulltb<2;nulltb++)for(int skip=0;skip<2;skip++)for(int align=0;align<3;align++){
  uint32_t code[128],*out=code;unsigned char expected[sizeof(mem)];
  for(unsigned i=0;i<sizeof(mem);i++)mem[i]=(unsigned char)(i*13+(i>>8));
  memcpy(expected,mem,sizeof(mem));memset(r,0,sizeof(r));subop=0;
  for(int i=0;i<6;i++)env.segs[i].base=32*(i+1);
  r[rax_index]=UINT64_C(0x9876543210abcdef);r[rsi_index]=128+align;r[rdi_index]=2048+align;
  int id=targets[k],width=k==0?2:k==1?4:8;
  FastTemplateFields f={.id=id,.segment=seg,.addr32=a32,.skip_flags=skip};TranslationBlock tb={.flags=mode?HF_CS64_MASK:0};
  bool direct=EXPECT_LATS&&mode&&!nulltb&&!a32;
  unsigned source=128+align+((seg<0||(direct&&seg!=fs_index&&seg!=gs_index))?0:env.segs[seg].base);
  unsigned dest=2048+align+(direct?0:env.segs[es_index].base);
  uint64_t sv=0,dv=0,acc=r[rax_index];memcpy(&sv,expected+source,width);memcpy(&dv,expected+dest,width);
  if(k<2)memcpy(expected+dest,&sv,width);if(k==3)memcpy(expected+dest,&acc,width);
  assert(ft_emit_string_body(&out,&f,width,nulltb?NULL:&tb));
  assert(!memcmp(mem,expected,sizeof(mem)));assert(r[rsi_index]==128+align&&r[rdi_index]==2048+align);
  assert(r[rax_index]==(k==2?sv:acc));
  if(k==4||k==5){assert(r[la_t0]==((k==4?sv:acc)^dv));if(!skip)assert(subop&&sub0==(k==4?sv:acc)&&sub1==dv);else assert(!subop);}
  if(direct&&seg!=fs_index&&seg!=gs_index){int expected_count=k<2?2:k==2?1:k==3?1:k==4?(skip?3:4):(skip?2:3);assert(out-code==expected_count);}
  n++;
 }
 printf("string body mode/segment/addr32/flags cases=%u LATS=%d PASS\n",n,EXPECT_LATS);
}
"""
with tempfile.TemporaryDirectory() as d:
 c=Path(d)/'test.c';c.write_text(header+helpers+body+main)
 for label,flags in [('lats',['-DCONFIG_SOFTMMU=1','-DEXPECT_LATS=1']),('latu',['-DCONFIG_SOFTMMU=1','-DQUICKTRANS_LATU=1','-DEXPECT_LATS=0']),('user',['-DEXPECT_LATS=0'])]:
  exe=Path(d)/label;subprocess.run([os.environ.get('CC','cc'),'-std=c99','-O2','-Werror','-fsanitize=undefined',*flags,str(c),'-o',str(exe)],check=True);subprocess.run([str(exe)],check=True)
