/^### mem mode=/ { split($3,a,"="); m=a[2] }
/maximum resident set size/ { printf "mode %s  max RSS         %.2f GiB\n", m, $1/1073741824 }
/peak memory footprint/     { printf "mode %s  peak footprint  %.2f GiB\n", m, $1/1073741824 }
