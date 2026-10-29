#!/usr/bin/env python3
"""Check startup flag semantics, repeated reads and concurrent first use."""
from pathlib import Path
import os, subprocess, tempfile
root = Path(__file__).resolve().parents[1]
src = (root/'src/emitter/fast_translator/fast-translator.c').read_text()
a = src.index('enum {\n    FT_STARTUP_READY')
b = src.index('#include "emit-core.inc.c"', a)
body = src[a:b]
head = r'''
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <assert.h>
static unsigned calls;
static unsigned expected;
static char *count_getenv(const char *name) {
 __atomic_add_fetch(&calls, 1, __ATOMIC_RELAXED);
 return getenv(name);
}
static bool quicktrans_profile_exit_cleanup_required(void) { return PROFILE; }
static bool quicktrans_stats_requested(void) {
 const char *v=count_getenv("LATX_QUICKTRANS_STATS");
 return v && (!strcmp(v,"1") || !strcmp(v,"yes"));
}
#define getenv count_getenv
'''
tail = r'''
#undef getenv
static void *worker(void *unused) {
 for(int i=0;i<10000;i++) assert(ft_startup_flags()==expected);
 return NULL;
}
int main(int argc,char **argv) {
 expected=strtoul(argv[1],0,0);
 if(argc>2) { pthread_t t[8]; for(int i=0;i<8;i++)assert(!pthread_create(t+i,0,worker,0));
  for(int i=0;i<8;i++)pthread_join(t[i],0); }
 assert(ft_startup_flags()==expected);
 unsigned n=calls;
 for(int i=0;i<10000;i++)assert(ft_startup_flags()==expected);
 assert(calls==n);
 setenv("LATX_FT_TU_TRACE","1",1);
 assert(ft_startup_flags()==expected); /* startup settings stay frozen */
 assert(calls==n);
 return 0;
}
'''
keys=['LATX_QUICKTRANS_STATS','LATX_TRANSLATOR_STATS','LATX_FT_TU_STATS',
      'LATX_FT_TU_DIRECT_STATS','LATX_FT_TU_TRACE','LATX_FT_TU_DIRECT_TRACE',
      'LATX_FT_TB_KIND_TRACE']
count=0
with tempfile.TemporaryDirectory() as tmp:
 p=Path(tmp); (p/'test.c').write_text(head+body+tail)
 for debug in [False, True]:
  for soft,profile in [(0,0),(0,1),(1,0)]:
   exe=p/('test-%s-%s'%(soft,profile))
   subprocess.run(['cc','-O2','-pthread','-DPROFILE='+str(profile),
        *(['-DCONFIG_LATX_DEBUG'] if debug else []),
        *(['-DCONFIG_SOFTMMU'] if soft else []),str(p/'test.c'),'-o',str(exe)],check=True)
   for mask in range(128):
    env=dict(os.environ)
    for k in keys:env.pop(k,None)
    for i,k in enumerate(keys):
     if mask&(1<<i):env[k]='1' if i==0 else ''
    expected=1 | (2 if not soft and (profile or mask&(15 if debug else 3)) else 0)
    if debug:
     expected |= (4 if mask&16 else 0)|(8 if mask&32 else 0)|(16 if mask&64 else 0)
    subprocess.run([str(exe),str(expected),*(['threads'] if mask in (0,127) else [])],env=env,check=True)
    count+=1
   env=dict(os.environ)
   for k in keys:env.pop(k,None)
   env[keys[0]]='0'
   subprocess.run([str(exe),str(3 if profile and not soft else 1)],env=env,check=True)
   count+=1
print('PASS',count,'startup configurations, cached repeats and concurrent first use')
