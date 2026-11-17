# Condition flags across guest page faults

`fault-gap-flags.S` is a Linux x86-64 guest regression, not a host-only emitter
check. A folded comparison must not lose its architectural flags if a later
memory access faults and execution resumes in a newly translated block.

Build on x86-64, or use an x86-64 cross compiler:

```sh
for n in 1 2 3 4; do
    gcc -nostdlib -static -DCASE=$n fault-gap-flags.S -o fault-gap-$n
done
```

Run the four executables as an ordinary user inside an x86-64 Linux guest under
LATS/HAMT with strict Quicktrans enabled and AOT disabled. Use a fresh process
for each case; do not pre-touch the data page. Exit zero means correct results.
The page-aligned data access intentionally faults on its first read or write.
No root permissions, sysctl changes, or deliberate fatal signal are needed.

| CASE | Access that can fault after the comparison |
| --- | --- |
| 1 | MOV store between CMP and register SETNE |
| 2 | MOV load between CMP and register SETNE |
| 3 | Memory destination of SETNE |
| 4 | Memory source of CMOVNE, including its false-condition read |

All four cases pass on native x86-64. The affected Quicktrans version returns
1, 1, 1 and 85 respectively; corrected Quicktrans returns zero for all four.
Also compare against the unmodified binary's legacy translation path: a legacy
failure must be recorded independently, not silently treated as a valid oracle.

These tests exercise fault recovery and result correctness. They do not measure
performance or prove correctness for every asynchronous interruption. In
particular, successful non-faulting register-only folding remains enabled.
