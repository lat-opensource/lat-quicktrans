#!/usr/bin/env python3
"""Execute the real straight-line emitters through a scalar LA model.
Exhaust all saved tag words, TOPs, environment formats and transfer directions.
This checks emitted operation semantics/counts, not guest faults or performance.
"""
import os
from pathlib import Path
import subprocess
import tempfile
root = Path(__file__).resolve().parents[1]
text = (root / 'src/emitter/fast_translator/emit-x87-soft-env.inc.c').read_text()
def function(name):
    start = text.rindex('static void ', 0, text.index(name + '('))
    begin = text.index('{', start); end = begin + 1; depth = 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}'); end += 1
    return text[start:end]
source = r'''
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stddef.h>
static uint64_t r[8];
static unsigned char mem[4096], expected[4096];
static unsigned count, stores, top_loads;
enum {la_zero, la_t0, la_t1, la_t2, la_t3, la_t4, la_s0};
#define lsenv_offset_of_top(e) 0
#define lsenv_offset_of_tag_word(e) 8
#define lsenv_offset_of_fpr(e,i) (32+16*(i))
static uint64_t mask(int hi,int lo){return (UINT64_MAX >> (63-hi+lo)) << lo;}
static uint64_t ld(int base,int off,int n){uint64_t v=0; assert(r[base]+off+n<=sizeof(mem));memcpy(&v,mem+r[base]+off,n);return v;}
static void st(int src,int base,int off,int n){assert(r[base]+off+n<=sizeof(mem));memcpy(mem+r[base]+off,&r[src],n);stores++;}
#define EMIT(op) do {op;count++;} while(0)
#define FT_LA_OR_EMIT(o,d,a,b) EMIT(r[d]=r[a]|r[b])
#define FT_LA_XORI_EMIT(o,d,a,v) EMIT(r[d]=r[a]^(v))
#define FT_LA_SLTUI_EMIT(o,d,a,v) EMIT(r[d]=r[a]<(v))
#define FT_LA_BSTRPICK_D_EMIT(o,d,a,h,l) EMIT(r[d]=(r[a]&mask(h,l))>>(l))
#define FT_LA_BSTRINS_D_EMIT(o,d,a,h,l) EMIT(r[d]=(r[d]&~mask(h,l))|((r[a]<<(l))&mask(h,l)))
#define FT_LA_LD_WU_EMIT(o,d,b,v) EMIT(r[d]=ld(b,v,4); if((b)==la_s0&&(v)==0)top_loads++)
#define FT_LA_LD_W_EMIT FT_LA_LD_WU_EMIT
#define FT_LA_ORI_EMIT(o,d,a,v) EMIT(r[d]=r[a]|(v))
#define FT_LA_ST_W_EMIT(o,s,b,v) EMIT(st(s,b,v,4))
#define FT_LA_LD_D_EMIT(o,d,b,v) EMIT(r[d]=ld(b,v,8))
#define FT_LA_LD_HU_EMIT(o,d,b,v) EMIT(r[d]=ld(b,v,2))
#define FT_LA_ST_D_EMIT(o,s,b,v) EMIT(st(s,b,v,8))
#define FT_LA_ST_B_EMIT(o,s,b,v) EMIT(st(s,b,v,1))
#define FT_LA_SRLI_D_EMIT(o,d,a,v) EMIT(r[d]=r[a]>>(v))
#define FT_LA_ST_H_EMIT(o,s,b,v) EMIT(st(s,b,v,2))
#define FT_LA_ADDI_D_EMIT(o,d,a,v) EMIT(r[d]=r[a]+(v))
#define FT_LA_AND_EMIT(o,d,a,b) EMIT(r[d]=r[a]&r[b])
#define FT_LA_ANDI_EMIT(o,d,a,v) EMIT(r[d]=r[a]&(v))
#define FT_LA_SLLI_D_EMIT(o,d,a,v) EMIT(r[d]=r[a]<<(v))
#define FT_LA_ADD_D_EMIT(o,d,a,b) EMIT(r[d]=r[a]+r[b])
'''
source += r'''
#define lsenv_offset_of_control_word(e) 4
#define lsenv_offset_of_status_word(e) 6
#define lsenv_offset_of_fp_status(e) 168
typedef struct {unsigned char float_rounding_mode, floatx80_rounding_precision; unsigned short float_exception_flags; unsigned char flush_inputs_to_zero, flush_to_zero;} float_status;
#define FT_LA_OPCODE_ST_B 1
#define FT_LA_BSTRPICK_W_EMIT FT_LA_BSTRPICK_D_EMIT
#define ft_emit_store_env(o,s,off,op) FT_LA_ST_B_EMIT(o,s,la_s0,off)
static void ft_soft_env_status(uint32_t **out,int sw,int cw){
 (void)out;
 unsigned top=(r[sw]>>11)&7, v=r[sw]&0x47ff;
 v|=(v&0x80)<<8;if(v&~r[cw]&0x3f)v|=0x8080;
 memcpy(mem+r[la_s0],&top,4);memcpy(mem+r[la_s0]+6,&v,2);
 r[sw]=v;r[la_t3]=0xdeadbeef; /* allowed scratch clobber */
}
'''
source += '#define FT_LA_ADDI_W_EMIT FT_LA_ADDI_D_EMIT\n'
source += r'''
typedef struct {float_status sse_status; unsigned char padding[176]; uint16_t fpcs,fpds; uint64_t fpip,fpdp;} CPUX86State;
typedef struct {int unused;} FastBranchLabel, FastBranchFixup;
static bool use_tcg;
#define tcg_enabled() use_tcg
#define float_flag_output_denormal 64
#define FT_BRANCH_BEQ 0
#define FT_LA_OPCODE_ST_H 2
#define FT_LA_OPCODE_LD_BU 3
#define FT_LA_SLLI_W_EMIT FT_LA_SLLI_D_EMIT
#define FT_LA_BSTRINS_W_EMIT FT_LA_BSTRINS_D_EMIT
#define ft_emit_load_env(o,d,off,op) FT_LA_LD_HU_EMIT(o,d,la_s0,off)
#define ft_emit_branch_placeholder(o,f,k,a,b,l) ((void)(f),(void)(l))
#define ft_bind_branch_label(l,o) ((void)(l))
#define ft_resolve_branch_fixup(f) ((void)(f))
'''
source += function('ft_soft_env_sse_status') + '\n'
saved_text = text
text = (root / 'src/emitter/fast_translator/emit-x87-soft-fast.inc.c').read_text()
source += function('ft_soft_x87_zero') + '\n'
text = (root / 'src/emitter/fast_translator/emit-x87.inc.c').read_text()
state = text[text.index('    case FT_FNINIT:'):text.index('    case FT_FNCLEX:')]
assert state.index('ft_emit_x87_fast_init(&out)') < state.index('FT_LA_X86MTTOP_EMIT(&out, 0)')
assert 'break;' in state[:state.index('FT_LA_X86MTTOP_EMIT(&out, 0)')]
assert all(name in state for name in ['lsenv_offset_of_control_word', 'lsenv_offset_of_status_word', 'lsenv_offset_of_top', 'lsenv_offset_of_tag_word'])

source += r'''
static uint32_t fcsr; static unsigned hwtop;
#define FCSR_OFF_RM 8
#define floatx80_precision_x 0
#define FT_LA_X86MTTOP_EMIT(o,v) EMIT(hwtop=(v))
#define FT_LA_MOVFCSR2GR_EMIT(o,d,f) EMIT(r[d]=fcsr)
#define FT_LA_MOVGR2FCSR_EMIT(o,f,s) EMIT(fcsr=r[s])
#define ft_emit_li64(o,d,v) EMIT(r[d]=(uint64_t)(v))
'''
source += function('ft_emit_x87_fast_init') + '\n'
text = saved_text
source += function('ft_soft_bcd_pop') + '\n'
source += function('ft_soft_env_fxrestore_fpu') + '\n'
source += function('ft_soft_env_regs') + '\n' + function('ft_soft_env_restore_tags')
source += r'''
int main(void){
 for(unsigned sample=0;sample<65536;sample++) {
  for(unsigned i=0;i<sizeof(mem);i++)mem[i]=(i*37+sample)&255;
  memset(r,0,sizeof(r));r[la_s0]=256;memcpy(expected,mem,sizeof(mem));
  uint16_t cw=0x37f;memcpy(expected+260,&cw,2);memset(expected+262,0,2);
  memset(expected+256,0,4);memset(expected+264,1,8);
  expected[424]=0;expected[425]=floatx80_precision_x;
  memset(expected+256+offsetof(CPUX86State,fpcs),0,2);
  memset(expected+256+offsetof(CPUX86State,fpds),0,2);
  memset(expected+256+offsetof(CPUX86State,fpip),0,8);
  memset(expected+256+offsetof(CPUX86State,fpdp),0,8);
  uint32_t before=sample*0x98761u;fcsr=before;hwtop=7;count=stores=0;
  ft_emit_x87_fast_init(NULL);
  assert(hwtop==0 && fcsr==(before&~(3u<<FCSR_OFF_RM)));
  assert(!memcmp(mem,expected,sizeof(mem)));
 }

 for(unsigned top=0;top<256;top++){
  memset(mem,0xa5,sizeof(mem));memset(r,0,sizeof(r));r[la_s0]=256;memcpy(mem+256,&top,4);memcpy(expected,mem,sizeof(mem));
  unsigned next=(top-1)&7;memcpy(expected+256,&next,4);expected[264+next]=0;
  memset(expected+288+next*16,0,10);
  count=stores=0;ft_soft_x87_zero(NULL);
  assert(!memcmp(mem,expected,sizeof(mem)));assert(count==10&&stores==4);
 }

 for(int tcg=0;tcg<2;tcg++)for(int restore=0;restore<2;restore++)for(unsigned flags=0;flags<256;flags++){
  if(tcg && restore)continue;
  memset(mem,flags,sizeof(mem));memset(r,0,sizeof(r));r[la_s0]=256;r[la_t1]=0x1f80;
  memcpy(expected,mem,sizeof(mem));count=stores=0;use_tcg=tcg;
  ft_soft_env_sse_status(NULL,restore);
  assert(count==0 && stores==0 && r[la_t1]==0x1f80);
  assert(!memcmp(mem,expected,sizeof(mem)));
 }

 for(unsigned top=0;top<256;top++){
  memset(mem,0xa5,sizeof(mem));memset(r,0,sizeof(r));r[la_s0]=256;memcpy(mem+256,&top,4);memcpy(expected,mem,sizeof(mem));
  unsigned next=((top&7)+1)&7;memcpy(expected+256,&next,4);expected[264+(top&7)]=1;
  count=stores=0;ft_soft_bcd_pop(NULL);assert(!memcmp(mem,expected,sizeof(mem)));assert(count==8&&stores==2);
 }

 for(int fx=0;fx<2;fx++)for(unsigned tag=0;tag<(fx?256:65536);tag++){
  memset(mem,0xa5,sizeof(mem));memset(r,0,sizeof(r));r[la_s0]=256;r[la_t0]=tag;
  memcpy(expected,mem,sizeof(mem));
  for(int i=0;i<8;i++)expected[264+i]=fx?!((tag>>i)&1):(((tag>>(2*i))&3)==3);
  count=stores=0;ft_soft_env_restore_tags(NULL,fx);
  assert(!memcmp(mem,expected,sizeof(mem)));assert(stores==(fx?8:1));assert(count==(fx?25:20));
 }
 for(int fx=0;fx<2;fx++)for(int restore=0;restore<2;restore++)for(int top=0;top<8;top++)for(int data32=0;data32<2;data32++){
  for(unsigned i=0;i<sizeof(mem);i++)mem[i]=(i*37+i/11)&255;
  memset(r,0,sizeof(r));r[la_s0]=256;r[la_t4]=1024;memcpy(mem+256,&top,4);memcpy(expected,mem,sizeof(mem));
  int off=fx?32:(14<<data32);
  for(int i=0;i<8;i++){
   int env=256+32+((top+i)&7)*16, image=1024+off+i*(fx?16:10);
   memcpy(expected+(restore?env:image),mem+(restore?image:env),10);
  }
  count=stores=top_loads=0;ft_soft_env_regs(NULL,restore,fx,off);
  assert(!memcmp(mem,expected,sizeof(mem)));assert(top_loads==(fx?8:1));assert(count==(fx?72:(restore?56:65)));
 }

 for(unsigned sample=0;sample<65536;sample++){
  for(unsigned i=0;i<sizeof(mem);i++)mem[i]=(i*37+sample)&255;
  memset(r,0,sizeof(r));r[la_s0]=256;r[la_t4]=1024;
  uint16_t cw=sample,sw=(sample*109+31)&65535;unsigned tag=(sample>>3)&255;
  memcpy(mem+1024,&cw,2);memcpy(mem+1026,&sw,2);mem[1028]=tag;
  memcpy(expected,mem,sizeof(mem));
  unsigned top=(sw>>11)&7,status=sw&0x47ff;status|=(status&0x80)<<8;
  if(status&~cw&0x3f)status|=0x8080;
  memcpy(expected+256,&top,4);memcpy(expected+260,&cw,2);memcpy(expected+262,&status,2);
  unsigned pc=(cw>>8)&3;expected[424]=(cw>>10)&3;expected[425]=(pc?pc:1)^3;
  for(int i=0;i<8;i++){
   expected[264+i]=!((tag>>i)&1);
   memcpy(expected+288+((top+i)&7)*16,mem+1056+16*i,10);
  }
  count=stores=top_loads=0;ft_soft_env_fxrestore_fpu(NULL);
  assert(!memcmp(mem,expected,sizeof(mem)));assert(top_loads==1);
 }
 puts("passed: 65792 tag words, 64 transfers; packed legacy tags/TOP; 65536 FXRSTOR headers");
}
'''
with tempfile.TemporaryDirectory(prefix='qt-env-transfer-') as tmp:
    c = Path(tmp)/'test.c'; exe=Path(tmp)/'test';c.write_text(source)
    subprocess.run([os.environ.get('CC','cc'),'-std=c11','-O2','-Wall','-Wextra','-Wno-unused-parameter',str(c),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True)
