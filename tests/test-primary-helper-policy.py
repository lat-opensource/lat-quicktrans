#!/usr/bin/env python3
"""Fail if helper policy diverges from the primary fast-path assumption."""
from pathlib import Path
import re,sys,json
p=Path(sys.argv[1]);s=p.read_text();a=s.index('static bool ft_template_is_helper(FastTemplateKind kind)\n{');b=s.index('static bool ft_template_primary_helper_allowed(FastTemplateKind kind)\n{',a)
f=s[a:b];g=s[b:s.index('\n}',b)+2]
assert not re.search(r'^#',f+g,re.M)
x=set(re.findall(r'case (FT_\w+):',f));y=set(re.findall(r'kind == (FT_\w+)',g));assert x and x==y,(x-y,y-x)
print(json.dumps({'equal':True,'count':len(x),'kinds':sorted(x)}))
