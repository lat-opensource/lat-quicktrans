#!/usr/bin/env python3
"""Execute selected actual INC/DEC and LEA bodies in three macro modes.
Public memory helpers and flag ISA are modeled; real guest probes verify them.
Not a full LATU build. --optimized checks LATS local instruction counts.
"""
import ast,os,subprocess,tempfile,sys
from pathlib import Path
R=Path(__file__).resolve().parents[1];g=(R/'src/emitter/fast_translator/emit-gpr.inc.c').read_text();t=(R/'src/emitter/fast_translator/emit-template.inc.c').read_text()
tree=ast.parse((R/'tests/test-mov-not-direct.py').read_text());header=next(ast.literal_eval(x.value) for x in tree.body if isinstance(x,ast.Assign) and any(isinstance(y,ast.Name) and y.id=='header' for y in x.targets))
header=header.replace('int d=f->modrm_rm;FT_LA_OR_EMIT(o,d,s,la_zero);','int d=f->modrm_rm;uint64_t old=r[d];FT_LA_OR_EMIT(o,d,s,la_zero);').replace('r[d]=(r[d]&~mask)|(r[s]&mask);','r[d]=(old&~mask)|(r[s]&mask);')
header=header.replace('segment,addr32,size,disp;','segment,addr32,size,disp,skip_flags,sib,index,base,has_index,scale;')
header=header.replace('static uint32_t ft_gpr3_imm12(int op,int d,int s,int i){return 0;}','static uint32_t ft_gpr3_imm12(int op,int d,int s,int i){r[d]=op==FT_LA_OPCODE_ADDI_W?(uint64_t)(int64_t)(int32_t)(r[s]+i):r[s]+i;return 0;}')
header=header.replace('FT_LA_OPCODE_LU12I_W=1,','FT_LA_OPCODE_ADDI_W=1000,FT_LA_OPCODE_ADDI_D,FT_LA_OPCODE_LU12I_W=1,')
header+=r'''
enum {FT_LEA_R32_M=200,FT_LEA_R16_M,FT_LA_OPCODE_X86INC_B=8,FT_LA_OPCODE_X86INC_H=16,FT_LA_OPCODE_X86INC_W=32,FT_LA_OPCODE_X86INC_D=64,FT_LA_OPCODE_X86DEC_B=108,FT_LA_OPCODE_X86DEC_H=116,FT_LA_OPCODE_X86DEC_W=132,FT_LA_OPCODE_X86DEC_D=164};
static uint64_t flags;
static uint64_t incflags(uint64_t v,int w,bool inc){uint64_t m=w==64?UINT64_MAX:(1ULL<<w)-1,a=v&m,z=(a+(inc?1:-1))&m;return (flags&1)|((!__builtin_parity((unsigned char)z))<<2)|((!!((a^z)&16))<<4)|((z==0)<<6)|(((z>>(w-1))&1)<<7)|((a==(inc?(1ULL<<(w-1))-1:1ULL<<(w-1)))<<11);}
static uint32_t ft_gpr2(int op,int s,int z){bool inc=op<100;int w=inc?op:op-100;assert(z==la_zero);flags=incflags(r[s],w,inc);return 0;}
#define FT_LA_ADDI_W_EMIT(o,d,s,i) do{r[d]=(uint64_t)(int64_t)(int32_t)(r[s]+(i));T(o);}while(0)
#define FT_LA_ADDI_D_EMIT(o,d,s,i) do{r[d]=r[s]+(i);T(o);}while(0)
#define FT_LA_ADD_D_EMIT(o,d,s,t) do{r[d]=r[s]+r[t];T(o);}while(0)
#define FT_LA_SLLI_D_EMIT(o,d,s,i) do{r[d]=r[s]<<(i);T(o);}while(0)
/* LoongArch sa2 encodes shift-1; matches operand-address.inc.c usage. */
#define FT_LA_ALSL_D_EMIT(o,d,s,t,i) do{r[d]=(r[s]<<((i)+1))+r[t];T(o);}while(0)
#define ft_sib_has_index(f) ((f)->has_index)
#define ft_sib_index_index(f) ((f)->index)
#define ft_sib_scale(f) ((f)->scale)
#define ft_fits_simm12(v) ((v)>=-2048&&(v)<=2047)
static bool ft_base_from_modrm_sib_with_index(const FastTemplateFields*f,int*b){*b=f->base;return *b<16;}
#define ft_base_from_modrm_sib ft_base_from_modrm_sib_with_index
static bool ft_emit_li32(uint32_t**o,int d,uint32_t v){r[d]=(uint64_t)(int64_t)(int32_t)v;T(o);return true;}
'''
start=g.index('        if (!(is_64 ? ft_emit_load_rm64',g.index('static int ft_emit_inc_dec_template('));end=g.index('    case FT_INC_RM8:',start);wide=g[start:end]
start=g.index('        if (!ft_emit_load_rm8',end);end=g.index('    default:',start);small=g[start:end]
lea=t[t.index('    case FT_LEA_R32_M:'):t.index('    case FT_',t.index('    case FT_LEA_R16_M:')+len('    case FT_LEA_R16_M:'))]
main=r'''
int main(void){unsigned count=0;uint64_t edges[]={0,1,15,16,0x7f,0x80,0xff,0x7fff,0x8000,0xffff,0x7fffffff,0x80000000,0xffffffff,0x7fffffffffffffffULL,0x8000000000000000ULL,UINT64_MAX,0xdeadbeef12345678ULL};
for(int w=8;w<=64;w*=2)for(int inc=0;inc<2;inc++)for(int dst=0;dst<16;dst++)for(int j=0;j<17;j++)for(int dead=0;dead<2;dead++)for(int memory=0;memory<2;memory++)for(int cf=0;cf<2;cf++){
 uint64_t v=edges[j],mask=w==64?UINT64_MAX:(1ULL<<w)-1;for(int k=0;k<32;k++)r[k]=0xabbacddc87654321ULL;r[31]=0;r[dst]=v;mem=v;loads=stores=0;flags=0x8d4|cf;uint64_t expectedflags=incflags(v,w,inc);FastTemplateFields f={.modrm_mod=memory?0:3,.modrm_rm=dst,.skip_flags=dead};uint32_t code[128];int n=emit_inc(&f,inc,w,code);uint64_t z=(v+(inc?1:-1))&mask;assert((memory?mem:r[dst])==(memory||w<32?(v&~mask)|z:z));assert(flags==((INC_CHANGED&&EXPECT_LOCAL&&!memory&&w>=32&&dead)?(0x8d4|cf):expectedflags));assert((flags&1)==cf);if(OPTIMIZED&&!memory&&w>=32)assert(n==(w==32?2:1)+(EXPECT_LOCAL?!dead:2));if(memory)assert(loads==1&&stores==1&&r[dst]==v);count++;
}
int disps[]={0,7,-7,2047,-2048,2048,-2049,2147483647,(-2147483647-1)};
for(int w=16;w<=32;w*=2)for(int d=0;d<16;d++)for(int b=0;b<16;b++)for(int idx=0;idx<16;idx++)for(int sc=0;sc<4;sc++)for(int j=0;j<9;j++)for(int nb=0;nb<2;nb++){
 for(int k=0;k<32;k++)r[k]=0xabbacddc87654321ULL+k*0x1234567;r[31]=0;uint64_t old=r[d],z=(nb?0:r[b])+(r[idx]<<sc)+(int64_t)disps[j];z=w==16?(old&~65535ULL)|(z&65535):(uint32_t)z;flags=0x8d5;FastTemplateFields f={.kind=w==16?FT_LEA_R16_M:FT_LEA_R32_M,.prefix2=w==16?0x66:0,.modrm_mod=nb?0:2,.modrm_rm=4,.modrm_reg=d,.sib=nb?5:0,.index=idx,.base=b,.has_index=1,.scale=sc,.disp=disps[j],.addr32=j%2};uint32_t code[128];int n=emit_lea(&f,code);assert(n>0&&r[d]==z&&flags==0x8d5);if(OPTIMIZED&&EXPECT_LOCAL&&w==32&&!nb){int want=2+(disps[j]!=0)+(ft_fits_simm12(disps[j])?0:1);assert(n==want);}count++;
}
for(int w=16;w<=32;w*=2)for(int j=0;j<9;j++){
 uint64_t old=0xdeadbeef12345678ULL;for(int k=0;k<32;k++)r[k]=old;r[31]=0;flags=0x8d5;FastTemplateFields f={.kind=w==16?FT_LEA_R16_M:FT_LEA_R32_M,.prefix2=w==16?0x66:0,.modrm_mod=0,.modrm_rm=4,.modrm_reg=0,.sib=5,.has_index=0,.disp=disps[j]};uint32_t code[128];int n=emit_lea(&f,code);uint64_t z=w==16?(old&~65535ULL)|((uint16_t)disps[j]):EXPECT_LOCAL?(uint32_t)disps[j]:(uint64_t)(int64_t)(int32_t)disps[j];assert(n>0&&r[0]==z&&flags==0x8d5);count++;
}
printf("actual INC/DEC/LEA body %u cases PASS local-sequence=%d optimized=%d\n",count,EXPECT_LOCAL,OPTIMIZED);}
'''
code=header+'static int emit_inc(const FastTemplateFields*fields,bool is_inc,int w,uint32_t*code){uint32_t*out=code;int dst;bool is_64=w==64,is_16=w==16;do{if(w==8){'+small+'}else{'+wide+'}}while(0);return out-code;}\nstatic int emit_lea(const FastTemplateFields*fields,uint32_t*code){uint32_t*out=code;target_ulong pc=0x61000000;switch(fields->kind){'+lea+'default:return 0;}return out-code;}\n'+main
with tempfile.TemporaryDirectory() as d:
 c=Path(d)/'probe.c';c.write_text(code)
 for label,defs in [('lats',['-DCONFIG_SOFTMMU=1','-DEXPECT_LOCAL=1']),('latu',['-DCONFIG_SOFTMMU=1','-DQUICKTRANS_LATU=1','-DEXPECT_LOCAL=1']),('latu-native',['-DQUICKTRANS_LATU=1','-DEXPECT_LOCAL=1']),('user',['-DEXPECT_LOCAL=0'])]:
  e=Path(d)/label;subprocess.run([os.environ.get('CC','cc'),'-std=c99','-O2','-Werror',*(['-fsanitize=undefined'] if not os.environ.get('NO_SANITIZE') else []),'-DOPTIMIZED='+str(int('--optimized' in sys.argv)),'-DINC_CHANGED='+str(int('skip_flags only drops' in g)),*defs,str(c),'-o',str(e)],check=True);subprocess.run([str(e)],check=True)
