# In what conditions is the performance of the system "good" and in which is it "bad"? How does its performance compare to a Linux baseline (this discussion can be quantitative or qualitative)?

## Jack Umina

[The True Cost of Containing: A gVisor Case Study - Young](https://www.usenix.org/system/files/hotcloud19-paper-young.pdf)

#### gVisor takes a performance hit for...
- syscall heavy workloads
- memory-heavy applications
- large downloads using netstack

#### gVisor v. runc
- Simple syscalls 2.2x slower
- Memory allocations are 2.5x slower
- Opening and closing files on external tmpfs is 216x slower
- Reading small files 11x slower
- Downloading large files 2.8x slower
- Negatively affects high level operations like importing Python modules

## Jake Cannizzaro



## Jon Terry



## Sam Frey



## Will Daughtridge



