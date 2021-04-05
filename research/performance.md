## Jack Umina



## Jake Cannizzaro



## Jon Terry
- Performance is significantly worse for almost everything compared to Linux
- System calls:
    - Extra layer between applications and host OS results in more context switches and significant harm to performance
    - Sentry delegates to Gofer for open() calls on external(outside sandbox) tmpfs
    - gVisor syscalls vs. Linux performance:
        - implemented fully in gVisor: 2.2x slower
        - require host syscalls by gVisor: 9x slower
        - require call to Gofer: 72x slower
- Storage
    - open/close latency ridiculously high for external tmpfs
    - still slower than normal Linux for internal tmpfs
        - read/write slower, much slower for small reads/writes (Gofer not used for read/write - Sentry has handle to external files)
    - heavy use of internal tmpfs rather than requiring external tmpfs's improves performance of gVisor
- Memory
    - significantly less allocations/sec than Linux
    - mem-heavy applications will have bad performance
    - Sentry selects memory regions to demand from host, when app marks region as not needed Sentry releases mem back to host rather than retaining to use for some later request
  


## Sam Frey



## Will Daughtridge



