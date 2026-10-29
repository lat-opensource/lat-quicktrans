#!/usr/bin/env python3
"""Check fixed/patchable static calls and near/far displacement boundaries."""
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
text = (root / 'src/emitter/fast_translator/emit-exit.inc.c').read_text()
start = text.index('static void ft_emit_lats_static_call(')
end = text.index('\nstatic ', start + 1)
source = r'''
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
typedef uintptr_t ADDR;
static bool option_large_code_cache;
enum {la_ra = 1};
static int64_t displacement, captured_upper, captured_lower;
static int link_reg, scratch;
static bool int32_in_int26(int64_t n) {return n >= -(1LL<<25) && n < (1LL<<25);}
#define FT_LA_BL_EMIT(o,n) do {displacement=(n); *(*o)++=1;} while(0)
#define FT_LA_NOP_EMIT(o) do {*(*o)++=2;} while(0)
#define FT_LA_PCADDU18I_EMIT(o,r,n) do {scratch=(r);captured_upper=(n);*(*o)++=3;} while(0)
#define FT_LA_JIRL_EMIT(o,d,s,n) do {link_reg=(d);assert(scratch==(s));captured_lower=(n);*(*o)++=4;} while(0)
''' + text[start:end] + r'''
int main(void) {
    int64_t offsets[] = {0, 1, -1, (1LL<<25)-1, -(1LL<<25),
                         1LL<<25, -(1LL<<25)-1, 0x12345678, -0x12345678};
    for (int large=0;large<2;large++) for(int patch=0;patch<2;patch++)
    for(unsigned i=0;i<sizeof(offsets)/sizeof(offsets[0]);i++) {
        uint32_t code[3]={0,0,0}, *out=code;
        int64_t off=offsets[i];
        if (!large && !int32_in_int26(off)) continue;
        option_large_code_cache=large;
        ft_emit_lats_static_call(&out, (ADDR)code+off*4, 12, patch);
        if (int32_in_int26(off)) {
            assert(out-code==1+patch && code[0]==1 && displacement==off);
            if(patch) assert(code[1]==2);
        } else {
            assert(out-code==2 && code[0]==3 && code[1]==4);
            int64_t signed_upper=(captured_upper&0x80000)?captured_upper-0x100000:captured_upper;
            assert(signed_upper*65536+captured_lower==off && link_reg==la_ra);
        }
        assert(code[2]==0);
    }
}
'''
with tempfile.TemporaryDirectory() as td:
    p = Path(td)
    (p / 'test.c').write_text(source)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Werror',
                    str(p / 'test.c'), '-o', str(p / 'test')], check=True)
    subprocess.run([str(p / 'test')], check=True)
