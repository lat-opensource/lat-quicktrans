#!/usr/bin/env python3
"""Execute actual ADX/IMUL/MOVZX emitter operations against integer models.
Memory and LoongArch flag instructions are modeled; not an end-to-end guest test.
"""
import os, subprocess, tempfile
from pathlib import Path
root=Path(__file__).resolve().parents[1]
g=(root/'src/emitter/fast_translator/emit-gpr.inc.c').read_text()
a=(root/'src/emitter/fast_translator/emit-atomic-div.inc.c').read_text()
body=g[g.index('static int ft_emit_adx_template'):g.index('static int ft_emit_rdtsc_template')]
body+=a[a.index('static void ft_emit_flag2_if_live'):a.index('static int ft_emit_imul_unary_template')]
body+=g[g.index('static int ft_emit_movzx8_template'):g.index('static int ft_emit_sign_extend_acc_template')]
head=r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
enum {FT_ADCX_R32_RM32,FT_ADCX_R64_RM64,FT_ADOX_R32_RM32,FT_ADOX_R64_RM64,FT_IMUL_RM8,FT_IMUL_RM16,FT_IMUL_RM32,FT_IMUL_RM64,FT_MOVZX_R16_RM8,dt_X86_INS_ADOX,dt_X86_INS_ADCX,dt_X86_PREFIX_REP,dt_X86_PREFIX_OPSIZE,GPR_NUM=16,rax_index=0,rdx_index=2,la_t0=16,la_t1,la_t2,la_t3,la_t4,la_zero=31,CF_USEDEF_BIT=1,PF_USEDEF_BIT=4,AF_USEDEF_BIT=16,ZF_USEDEF_BIT=64,SF_USEDEF_BIT=128,OF_USEDEF_BIT=2048,FT_LA_OPCODE_X86MUL_B=8,FT_LA_OPCODE_X86MUL_H=16,FT_LA_OPCODE_X86MUL_W=32,FT_LA_OPCODE_X86MUL_D=64};
typedef struct {int kind,dst,src,modrm_mod,modrm_reg,id,prefix0,prefix2,size,disp;bool rex,skip_flags,high8,rip;} FastTemplateFields;
typedef int TranslationBlock;typedef uint64_t target_ulong;
static uint64_t r[32],flags,mem;static int count;
#define T(o) do{*(*(o))++=0;count++;}while(0)
#define ft_gpr(x) (x)
#define ft_rex_w(f) ((f)->rex)
#define ft_modrm_reg_index(f) ((f)->dst)
#define ft_modrm_rm_index(f) ((f)->src)
#define ft_modrm_rm_high8_base_index(f) ((f)->src)
#define ft_modrm_rm_is_high8(f) ((f)->high8)
#define ft_rip_relative_mem(f) ((f)->rip)
#define FT_LA_OR_EMIT(o,d,s,t) do{r[d]=r[s]|r[t];T(o);}while(0)
#define FT_LA_ADD_D_EMIT(o,d,s,t) do{r[d]=r[s]+r[t];T(o);}while(0)
#define FT_LA_ADD_W_EMIT(o,d,s,t) do{r[d]=(uint64_t)(int64_t)(int32_t)(r[s]+r[t]);T(o);}while(0)
#define FT_LA_EXT_W_B_EMIT(o,d,s) do{r[d]=(uint64_t)(int64_t)(int8_t)r[s];T(o);}while(0)
#define FT_LA_EXT_W_H_EMIT(o,d,s) do{r[d]=(uint64_t)(int64_t)(int16_t)r[s];T(o);}while(0)
#define FT_LA_SRLI_D_EMIT(o,d,s,k) do{r[d]=r[s]>>(k);T(o);}while(0)
#define FT_LA_BSTRPICK_D_EMIT(o,d,s,h,l) do{r[d]=(r[s]>>(l))&(UINT64_MAX>>(63-((h)-(l))));T(o);}while(0)
#define FT_LA_BSTRINS_D_EMIT(o,d,s,h,l) do{uint64_t m=(UINT64_MAX>>(63-((h)-(l))))<<(l);r[d]=(r[d]&~m)|((r[s]<<(l))&m);T(o);}while(0)
#define FT_LA_X86MFFLAG_EMIT(o,d,m) do{r[d]=flags;T(o);}while(0)
#define FT_LA_X86MTFLAG_EMIT(o,s,m) do{uint64_t mask=(m)==0x3f?0x8d5:(m);flags=(flags&~mask)|(r[s]&mask);T(o);}while(0)
static void adc(int w,int s,int t){__uint128_t mask=w==64?UINT64_MAX:UINT32_MAX,z=(r[s]&mask)+(r[t]&mask)+(flags&1);flags=(uint64_t)(z>>w);}
#define FT_LA_X86ADC_D_EMIT(o,s,t) do{adc(64,s,t);T(o);}while(0)
#define FT_LA_X86ADC_W_EMIT(o,s,t) do{adc(32,s,t);T(o);}while(0)
#define FT_LA_MUL_W_EMIT(o,d,s,t) do{r[d]=(uint64_t)(int64_t)(int32_t)((uint32_t)r[s]*(uint32_t)r[t]);T(o);}while(0)
#define FT_LA_MUL_D_EMIT(o,d,s,t) do{r[d]=r[s]*r[t];T(o);}while(0)
#define FT_LA_MULW_D_W_EMIT(o,d,s,t) do{r[d]=(uint64_t)((int64_t)(int32_t)r[s]*(int32_t)r[t]);T(o);}while(0)
#define FT_LA_MULH_D_EMIT(o,d,s,t) do{r[d]=(uint64_t)(((__int128)(int64_t)r[s]*(int64_t)r[t])>>64);T(o);}while(0)
static __int128 sx(uint64_t v,int w){return w==64?(int64_t)v:w==32?(int32_t)v:w==16?(int16_t)v:(int8_t)v;}
static uint32_t ft_gpr2(int w,int s,int t){__int128 z=sx(r[s],w)*sx(r[t],w),min=-((__int128)1<<(w-1)),max=-min-1;flags=(flags&~0x801ULL)|((z<min||z>max)?0x801:0);return 0;}
static void ft_emit_raw(uint32_t**o,uint32_t x){T(o);}
static bool load(uint32_t**o,const FastTemplateFields*f,int*s,int w){if(f->modrm_mod==3){*s=f->src;if(w==8&&f->high8){r[la_t0]=r[*s]>>8;*s=la_t0;T(o);}}else{r[la_t0]=w==64?mem:w==32?(uint64_t)(int64_t)(int32_t)mem:w==16?(uint16_t)mem:(uint8_t)mem;*s=la_t0;T(o);}return true;}
#define ft_emit_load_rm8(o,f,p,s) load(o,f,s,8)
#define ft_emit_load_rm16(o,f,p,s) load(o,f,s,16)
#define ft_emit_load_rm32(o,f,p,s) load(o,f,s,32)
#define ft_emit_load_rm64(o,f,p,s) load(o,f,s,64)
static bool ft_emit_guest_addr(uint32_t**o,int d,uint64_t p){r[d]=p;T(o);return true;}
static bool ft_emit_mem_addr(uint32_t**o,const FastTemplateFields*f,int*a){*a=la_t1;return true;}
static int ft_mem_access_offset(const FastTemplateFields*f,int a){return 0;}
#define FT_LA_LD_BU_EMIT(o,d,s,k) do{r[d]=(uint8_t)mem;T(o);}while(0)
'''
tail=r'''
static uint64_t seed=0xabc456987ULL;static uint64_t rnd(void){seed^=seed<<13;seed^=seed>>7;seed^=seed<<17;return seed;}
int main(void){unsigned cases=0;uint32_t code[128];uint64_t edges[]={0,1,0x7f,0x80,0x7fff,0x8000,0x7fffffff,0x80000000,0x7fffffffffffffffULL,0x8000000000000000ULL,UINT64_MAX};
for(int w=32;w<=64;w*=2)for(int adox=0;adox<2;adox++)for(int memory=0;memory<2;memory++)for(int d=0;d<16;d++)for(int s=0;s<16;s++)for(int j=0;j<16;j++)for(int cf=0;cf<2;cf++)for(int of=0;of<2;of++){
for(int k=0;k<32;k++)r[k]=rnd();r[31]=0;r[d]=j<11?edges[j]:rnd();r[s]=j<11?edges[10-j]:rnd();mem=j<11?edges[j]:rnd();uint64_t av=r[d],bv=memory?mem:r[s],mask=w==64?UINT64_MAX:UINT32_MAX;__uint128_t z=(__uint128_t)(av&mask)+(bv&mask)+(adox?of:cf);flags=(rnd()&0xd4)|cf|((uint64_t)of<<11);uint64_t wantflags=(flags&~(adox?2048ULL:1ULL))|((uint64_t)(z>>w)<<(adox?11:0));FastTemplateFields f={.kind=adox?(w==64?FT_ADOX_R64_RM64:FT_ADOX_R32_RM32):(w==64?FT_ADCX_R64_RM64:FT_ADCX_R32_RM32),.dst=d,.src=s,.modrm_mod=memory?0:3,.rex=w==64,.id=adox?dt_X86_INS_ADOX:dt_X86_INS_ADCX,.prefix0=adox?dt_X86_PREFIX_REP:0,.prefix2=adox?0:dt_X86_PREFIX_OPSIZE};count=0;int n=ft_emit_adx_template(&f,0,0,code);assert(n>0&&r[d]==((uint64_t)z&mask)&&flags==wantflags);assert(n==(adox?10:7)+2*memory);cases++;
}
for(int w=8;w<=64;w*=2)for(int memory=0;memory<2;memory++)for(int s=0;s<16;s++)for(int j=0;j<32;j++)for(int dead=0;dead<2;dead++){
for(int k=0;k<32;k++)r[k]=rnd();r[31]=0;r[0]=j<11?edges[j]:rnd();r[s]=j<11?edges[10-j]:rnd();mem=j<11?edges[j]:rnd();uint64_t olda=r[0],oldd=r[2];__int128 z=sx(olda,w)*sx(memory?mem:r[s],w);flags=0x8d5;__int128 min=-((__int128)1<<(w-1)),max=-min-1;uint64_t wantf=dead?flags:(flags&~0x801ULL)|((z<min||z>max)?0x801:0);FastTemplateFields f={.kind=w==8?FT_IMUL_RM8:w==16?FT_IMUL_RM16:w==32?FT_IMUL_RM32:FT_IMUL_RM64,.src=s,.modrm_reg=5,.modrm_mod=memory?0:3,.rex=w==64,.skip_flags=dead};uint32_t*out=code;count=0;assert(ft_emit_imul_unary(&out,&f,0));uint64_t wanta=w==8?(olda&~65535ULL)|((uint64_t)z&65535):w==16?(olda&~65535ULL)|((uint64_t)z&65535):w==32?(uint32_t)z:(uint64_t)z;uint64_t wantd=w==8?oldd:w==16?(oldd&~65535ULL)|(((uint64_t)z>>16)&65535):w==32?(uint32_t)(((__uint128_t)z)>>32):(uint64_t)(((__uint128_t)z)>>64);assert(r[0]==wanta&&r[2]==wantd&&flags==wantf);cases++;
}
for(int d=0;d<16;d++)for(int s=0;s<16;s++)for(int high=0;high<2;high++)for(int j=0;j<32;j++){
for(int k=0;k<32;k++)r[k]=rnd();r[31]=0;uint64_t want=(r[d]&~65535ULL)|((r[s]>>(high?8:0))&255);flags=0x8d5;FastTemplateFields f={.kind=FT_MOVZX_R16_RM8,.dst=d,.src=s,.high8=high,.modrm_mod=3};count=0;int n=ft_emit_movzx8_template(&f,0,0,code);assert(n==(d==s&&!high?1:2)&&r[d]==want&&flags==0x8d5);cases++;
}
printf("ADX/IMUL/MOVZX actual bodies: %u cases PASS (modeled memory/flags)\n",cases);
}
'''
with tempfile.TemporaryDirectory() as d:
 c=Path(d)/'integer.c';c.write_text(head+body+tail);exe=Path(d)/'integer'
 subprocess.run([os.environ.get('CC','cc'),'-std=c99','-O2','-Werror','-fsanitize=undefined','-fno-sanitize-recover=all',str(c),'-o',str(exe)],check=True)
 subprocess.run([str(exe)],check=True)
