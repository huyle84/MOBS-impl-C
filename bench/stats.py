import re,statistics as st,sys,json
log=open(sys.argv[1]).read()
res={}
for blk in re.split(r'^### ',log,flags=re.M)[1:]:
    m=re.match(r'mode=(\d) run=(\d+)',blk); mode=m.group(1)
    d=res.setdefault(mode,{})
    for name,val in re.findall(r'^\| ([A-Za-z0-9 ()=,]+?) \| ([0-9.]+) ms \|',blk,flags=re.M):
        d.setdefault(name.strip(),[]).append(float(val))
    r=re.search(r'^\| 8 \|.*\| ([0-9.]+) MiB \| ([0-9.]+) \+ ([0-9.]+) s \| ([0-9.]+) \+ ([0-9.]+) s',blk,flags=re.M)
    if r:
        d.setdefault('size',[]).append(float(r.group(1)))
        d.setdefault('open',[]).append(float(r.group(2))+float(r.group(3)))
        d.setdefault('verify',[]).append(float(r.group(4))+float(r.group(5)))
for mode,d in sorted(res.items()):
    print('mode',mode)
    for k,v in d.items():
        sd=st.stdev(v) if len(v)>1 else 0
        print(f'  {k:28s} n={len(v):2d} mean={st.mean(v):.4f} sd={sd:.4f} rsd={100*sd/st.mean(v):.2f}% min={min(v):.3f} max={max(v):.3f}')
