#!/usr/bin/env python3
"""Execute actual selected bodies in LATS/LATU/user. Memory and flags modeled;
guest probes separately test real decode, special flag instructions and memory.
"""
import ast,os,subprocess,tempfile,sys
from pathlib import Path
R=Path(__file__).resolve().parents[1];g=(R/'src/emitter/fast_translator/emit-gpr.inc.c').read_text()
# Reuse established load/store model, rather than duplicate its small-width logic.
tree=ast.parse((R/'tests/test-mov-not-direct.py').read_text());header=next(ast.literal_eval(x.value) for x in tree.body if isinstance(x,ast.Assign) and any(isinstance(y,ast.Name) and y.id=='header' for y in x.targets))
header=header.replace('int d=f->modrm_rm;FT_LA_OR_EMIT(o,d,s,la_zero);','int d=f->modrm_rm;uint64_t old=r[d];FT_LA_OR_EMIT(o,d,s,la_zero);').replace('r[d]=(r[d]&~mask)|(r[s]&mask);','r[d]=(old&~mask)|(r[s]&mask);')
header=header.replace('segment,addr32,size,disp;','segment,addr32,size,disp,high8,rip,skip_flags;')
header+=r'''
enum {FT_MOVSX_R64_RM8=100,FT_MOVSX_R32_RM8,FT_MOVSX_R16_RM8,FT_MOVSX_R64_RM16,FT_MOVSX_R32_RM16,FT_MOVSX_R16_RM16,FT_NEG_RM8,FT_NEG_RM16,FT_NEG_RM32,FT_NEG_RM64,FT_LA_OPCODE_X86SUB_D=64,FT_LA_OPCODE_X86SUB_W=32,FT_LA_OPCODE_X86SUB_H=16,FT_LA_OPCODE_X86SUB_B=8};
static uint64_t flags;
#define ft_modrm_rm_is_high8(f) ((f)->high8)
#define ft_modrm_rm_high8_base_index(f) ((f)->modrm_rm)
#define ft_rip_relative_mem(f) ((f)->rip)
#define FT_LA_EXT_W_B_EMIT(o,d,s) do{r[d]=(uint64_t)(int64_t)(int8_t)r[s];T(o);}while(0)
#define FT_LA_EXT_W_H_EMIT(o,d,s) do{r[d]=(uint64_t)(int64_t)(int16_t)r[s];T(o);}while(0)
#define FT_LA_SRAI_W_EMIT(o,d,s,i) do{r[d]=(uint64_t)(int64_t)((int32_t)r[s]>>(i));T(o);}while(0)
#define FT_LA_ADDI_W_EMIT(o,d,s,i) do{r[d]=(uint64_t)(int64_t)(int32_t)(r[s]+(i));T(o);}while(0)
#define FT_LA_SLLI_D_EMIT(o,d,s,i) do{r[d]=r[s]<<(i);T(o);}while(0)
#define FT_LA_SRAI_D_EMIT(o,d,s,i) do{r[d]=(uint64_t)((int64_t)r[s]>>(i));T(o);}while(0)
#define FT_LA_LD_B_EMIT(o,d,s,i) do{r[d]=(uint64_t)(int64_t)(int8_t)mem;loads++;T(o);}while(0)
#define FT_LA_LD_H_EMIT(o,d,s,i) do{r[d]=(uint64_t)(int64_t)(int16_t)mem;loads++;T(o);}while(0)
#define FT_LA_SUB_D_EMIT(o,d,s,t) do{r[d]=r[s]-r[t];T(o);}while(0)
#define FT_LA_SUB_W_EMIT(o,d,s,t) do{r[d]=(uint64_t)(int64_t)(int32_t)(r[s]-r[t]);T(o);}while(0)
static uint64_t negflags(uint64_t v,int w){uint64_t mask=w==64?UINT64_MAX:(1ULL<<w)-1,a=v&mask,z=(-a)&mask;return (!!a)|((!__builtin_parity((unsigned char)z))<<2)|((!!((a^z)&16))<<4)|((z==0)<<6)|(((z>>(w-1))&1)<<7)|((a==(1ULL<<(w-1)))<<11);}
#define FT_FLAG2(op,s,t) do{if(!fields->skip_flags){assert(r[s]==0);flags=negflags(r[t],op);T(&out);}}while(0)
'''
mov=g[g.index('static int ft_emit_movsx8_template('):g.index('static int ft_emit_movzx16_template(')]
# High8 real load helper emits SRLI; low8 is passed through and masked by shifts.
header=header.replace('#define ft_emit_load_rm8(o,f,p,s) load(o,f,s,8)','static bool load8(uint32_t**o,const FastTemplateFields*f,int*s){if(f->modrm_mod==3&&f->high8){r[16]=r[f->modrm_rm]>>8;*s=16;T(o);return true;}return load(o,f,s,8);}\n#define ft_emit_load_rm8(o,f,p,s) load8(o,f,s)')
x=g[g.index('            FT_LA_OR_EMIT(&out, la_t1, ft_gpr(dst), la_zero);',g.index('static int ft_emit_xchg_template(')):g.index('        } else {\n            int addr;',g.index('static int ft_emit_xchg_template('))]
neg=g[g.index('    switch (fields->kind) {',g.index('static int ft_emit_neg_template(')):g.index('static int ft_emit_inc_dec_template(')]
# Extract through the final case break, including a conditional early break.
start=g.index('        FT_LA_OR_EMIT(&out, la_t1, ft_gpr(reg), la_zero);',g.index('    case FT_XCHG_R64_RAX:'));end=g.index('    case FT_XCHG_R16_AX:',start);short=g[start:end];short=short[:short.rindex('        break;')]
header+='\nenum { rax_index=0, rdx_index=2, FT_CBW=200, FT_CWDE, FT_CDQE, FT_CQO, FT_CWD, FT_CDQ };\n'
acc=g[g.index('static int ft_emit_sign_extend_acc_template('):g.index('static int ft_emit_xlat_template(')]
main=r'''
int main(void){unsigned count=0;uint64_t edges[]={0,1,0x7f,0x80,0xff,0x7fff,0x8000,0xffff,0x7fffffff,0x80000000,0xffffffff,0x8000000000000000ULL,UINT64_MAX,0xdeadbeef12345678ULL};
for(int sw=8;sw<=16;sw+=8)for(int w=16;w<=64;w*=2)for(int dst=0;dst<16;dst++)for(int src=0;src<16;src++)for(int mode=0;mode<4;mode++)for(int j=0;j<14;j++){
 if(mode==3&&(sw!=8||src>3||w==64))continue;
 uint64_t seed=0xa55aa55a12345678ULL,v=edges[j]|0xdeadbeef00000000ULL;for(int k=0;k<32;k++)r[k]=seed;r[31]=0;r[src]=v;mem=v;loads=0;flags=0x8d5;
 FastTemplateFields f={.kind=sw==8?(w==64?FT_MOVSX_R64_RM8:w==32?FT_MOVSX_R32_RM8:FT_MOVSX_R16_RM8):(w==64?FT_MOVSX_R64_RM16:w==32?FT_MOVSX_R32_RM16:FT_MOVSX_R16_RM16),.rex=w==64,.prefix2=w==16?0x66:0,.modrm_mod=mode==1||mode==2?0:3,.modrm_reg=dst,.modrm_rm=src,.high8=mode==3,.rip=mode==2};
 uint64_t old=r[dst],a=mode==3?v>>8:v,z=sw==8?(uint64_t)(int64_t)(int8_t)a:(uint64_t)(int64_t)(int16_t)a;if(w==32)z=(uint32_t)z;if(w==16)z=(old&~65535ULL)|(z&65535);uint32_t code[128];int n=sw==8?ft_emit_movsx8_template(&f,0,0,code):ft_emit_movsx16_template(&f,0,0,code);assert(n>0&&r[dst]==z&&flags==0x8d5);if(OPTIMIZED&&w!=16){int short_sx=EXPECT_LOCAL||(LATU_MOVSX8&&sw==8);int want=(mode==1?1:mode==2?2:(short_sx?1:2)+(mode==3))+(w==32);assert(n==want+!short_sx);}if(OPTIMIZED&&w==16&&sw==8&&mode!=1&&mode!=2)assert(n==(EXPECT_LOCAL?2+(mode==3):4));count++;
}
for(int w=16;w<=64;w*=2)for(int d=0;d<16;d++)for(int s=0;s<16;s++)for(int j=0;j<14;j++){for(int k=0;k<32;k++)r[k]=0xaabbccdd87654321ULL;r[31]=0;r[s]=edges[j]|0xdeadbeef00000000ULL;uint64_t a=r[d],b=r[s];flags=0x8d5;uint32_t code[128];int n=emit_xchg(d,s,w,code);uint64_t da=w==32?(uint32_t)b:w==64?b:(a&~65535ULL)|(b&65535),sa=w==32?(uint32_t)a:w==64?a:(b&~65535ULL)|(a&65535);assert(r[d]==da&&r[s]==sa&&flags==0x8d5);if(OPTIMIZED)assert(n==(w==32?(EXPECT_LOCAL?3:5):3));count++;}
for(int w=8;w<=64;w*=2)for(int dst=0;dst<16;dst++)for(int j=0;j<14;j++)for(int dead=0;dead<2;dead++)for(int memory=0;memory<2;memory++){uint64_t v=edges[j];for(int k=0;k<32;k++)r[k]=0xa55aa55a12345678ULL;r[31]=0;r[dst]=v;mem=v;loads=stores=0;flags=0x8d5;FastTemplateFields f={.kind=w==64?FT_NEG_RM64:w==32?FT_NEG_RM32:w==16?FT_NEG_RM16:FT_NEG_RM8,.rex=w==64,.modrm_reg=3,.modrm_mod=memory?0:3,.modrm_rm=dst,.skip_flags=dead};uint32_t code[128];int n=emit_neg(&f,0,0,code);uint64_t mask=w==64?UINT64_MAX:(1ULL<<w)-1,z=(-v)&mask;if(memory)assert(mem==((v&~mask)|z)&&r[dst]==v&&loads==1&&stores==1);else assert(r[dst]==(w<32?(v&~mask)|z:z));assert(flags==(dead?0x8d5:negflags(v,w)));if(OPTIMIZED&&!memory&&w>=32)assert(n==(w==64?1:2)+!dead+(EXPECT_LOCAL?0:2));count++;}
for(int w=32;w<=64;w+=32)for(int reg=1;reg<16;reg++)for(int j=0;j<14;j++){for(int k=0;k<32;k++)r[k]=0xaabbccdd87654321ULL;r[31]=0;r[reg]=edges[j]|0xdeadbeef00000000ULL;uint64_t a=r[0],b=r[reg];flags=0x8d5;FastTemplateFields f={.rex=w==64};uint32_t code[128];int n=emit_short(&f,reg,code);assert(r[0]==(w==32?(uint32_t)b:b)&&r[reg]==(w==32?(uint32_t)a:a)&&flags==0x8d5);if(OPTIMIZED)assert(n==(w==32?(EXPECT_LOCAL?3:5):3));count++;}
for(int sw=8;sw<=16;sw+=8)for(int j=0;j<14;j++)for(int f=0;f<2;f++){uint64_t v=edges[j]|0xdeadbeef00000000ULL;r[0]=v;flags=f?0x8d5:0;uint64_t oldflags=flags,z=sw==8?(uint64_t)(int64_t)(int8_t)v:(uint64_t)(int64_t)(int16_t)v;uint64_t want=sw==8?(v&~65535ULL)|(z&65535):(uint32_t)z;FastTemplateFields fields={.kind=sw==8?FT_CBW:FT_CWDE};uint32_t code[16];int n=ft_emit_sign_extend_acc_template(&fields,0,0,code);assert(n>0&&r[0]==want&&flags==oldflags);if(OPTIMIZED)assert(n==(EXPECT_LOCAL?2:3));count++;}
printf("actual MOVSX/CBW/CWDE/XCHG/NEG %u cases PASS local-sequence=%d optimized=%d\n",count,EXPECT_LOCAL,OPTIMIZED);}
'''
code=header+acc+'static int emit_short(const FastTemplateFields*fields,int reg,uint32_t*code){uint32_t*out=code;do{'+short+'}while(0);return out-code;}\n'+mov+'\nstatic int emit_xchg(int dst,int src,int w,uint32_t*code){uint32_t*out=code;bool is16=w==16,is64=w==64;'+x+'return out-code;}\nstatic int emit_neg(const FastTemplateFields*fields,TranslationBlock*tb,target_ulong pc,uint32_t*code){uint32_t*out=code;int src;'+neg+main
with tempfile.TemporaryDirectory() as d:
 c=Path(d)/'probe.c';c.write_text(code)
 for label,defs in [('lats',['-DCONFIG_SOFTMMU=1','-DEXPECT_LOCAL=1']),('latu',['-DCONFIG_SOFTMMU=1','-DQUICKTRANS_LATU=1','-DEXPECT_LOCAL=1']),('latu-native',['-DQUICKTRANS_LATU=1','-DEXPECT_LOCAL=1']),('user',['-DEXPECT_LOCAL=0'])]:
  e=Path(d)/label;subprocess.run([os.environ.get('CC','cc'),'-std=c99','-O2','-Werror',*(['-fsanitize=undefined'] if not os.environ.get('NO_SANITIZE') else []),'-DOPTIMIZED='+str(int('--optimized' in sys.argv)),'-DLATU_MOVSX8='+str(int(label=='latu')),*defs,str(c),'-o',str(e)],check=True);subprocess.run([str(e)],check=True)
