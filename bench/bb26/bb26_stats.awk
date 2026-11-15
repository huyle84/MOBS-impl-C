/^#/ { g=$0; next }
/run=/ { for(i=1;i<=NF;i++){ split($i,a,"="); v[a[1]]=a[2] }
  n[g]++; b[g]=v["proof_bytes"]
  for(j=1;j<=3;j++){ f=F[j]; s[g,f]+=v[f]; q[g,f]+=v[f]^2 } }
BEGIN { split("commit_ms prove_ms verify_ms",F," ") }
END { for(k in n){ printf "%s  (n=%d, %s B)\n",k,n[k],b[k]
  for(j=1;j<=3;j++){ f=F[j]; m=s[k,f]/n[k]; sd=(n[k]>1)?sqrt((q[k,f]-n[k]*m*m)/(n[k]-1)):0
    printf "   %-10s %8.1f ± %.1f ms\n",f,m,sd } } }
