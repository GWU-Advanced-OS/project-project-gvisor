## Jack Umina



## Jake Cannizzaro



## Jon Terry



## Sam Frey
#### [Platform Guide](https://gvisor.dev/docs/architecture_guide/platforms/)
- Platform
    - ptrace
        - uses [PTRACE_SYSEMU](https://man7.org/linux/man-pages/man2/ptrace.2.html) to execute code without allowing sys calls to the host.
        - works anywhere that ptrace works (including VMs without nested virtualization)
        - Good option for maximum compatibility
        - high context switch overhead
    - KVM
        - Allows Sentry to act as both a guest OS and a VM manager
        - works directly with host or within a VM with nested virtualizatoin enabled.
        - Still a process-based model, but uses virtualization extentions on modern hardware for improved isolation and performance.

#### [Resource Model](https://gvisor.dev/docs/architecture_guide/resources/)
- Processes
    - A gVisor sandbox appears as one process on the host systems
    - Processes within the sandbox are not managed as individual host processes
        - process-level interactions with the sandbox require being in the sandbox (i.e. [docker exec](https://docs.docker.com/engine/reference/commandline/exec/)).
    - Sandboxes can expose network endpoints, by network introspection requires being in the sandbox
- Files
    - Files in the sandbox can be backed by multiple implementations
    - For host-native files (where a file descriptor is available), the Gofer may return a file descriptor to the Sentry via [SCM_RIGHTS](http://man7.org/linux/man-pages/man7/unix.7.html).
    - Files can be accessed with standard system calls for read and write.
    - Files can also be mapped into a sandboxed application's address space
        - allows shared mem between sandboxes
        - security issues??
    - Some file systems exist only within the sandbox (i.e `tmpfs` at `/tmp` or `/dev/shm`)
        - Counted against a sandbox's memory limits
- Threads
    - Sentry dispatches threads with [`goroutines`](https://tour.golang.org/concurrency/1)
        - Many-to-one thread model. gVisor threads may not correspond directly to a host thread.
        - Sentry schedules threads within a sandbox
        - Host threads are created depending on the number of active app threads in the sandbox.
        - In practice, a busy application will converge on the number of active threads, and the host will be able to make scheduling decisions about all application threads.
- Time
    - Provided by Sentry
        - Sentry provides a virtual dynamic shared object ([vDSO](https://en.wikipedia.org/wiki/VDSO)) to applications in the sandbox
            - apps in the sandbox can access time without switching to Sentry
        - No connection to host system time. At boot, sandbox time is initialized to the value of the host clock, but they are 2 completely separate entities beyond that.
        - Sentry runs timers to track passage of time for updating the vDSO, the time value returned by sys calls, and resource usage tracking ([RLIMIT_CPU](https://man7.org/linux/man-pages/man2/getrlimit.2.html)).
            - Similar to a standard kernel's timers, but software based.
        - When all app threads are idle, Sentry disables timers and waits for an event to wake an app thread or Sentry itself.
            - Similar to tickless kernel
            - Near zero CPU usage when idle
- Memory
    - Management by Sentry
    - includes demand-paging and a Sentry internal cache for files that can't be used natively with host file descriptors.
    - all application memory is backed by a single memfs
    - Address Spaces
        - creation is platform specific
        - For some platforms, additional “stub” processes may be created on the host in order to support additional address spaces. 
        - These stubs are subject to various limits applied at the sandbox level (e.g. PID limits).
    - Physical Memory
        - Host manages physical memory using standard means (e.g. tracking working sets, reclaiming and swapping under pressure).
        - Sentry lazily populates host mappings for applications, and allow the host to demand-page those regions, which is critical for the functioning of those mechanisms.
        - Sentry does not demand-page individual pages. Instead selects regions based on heuristics.
        - Sentry can't determine which pages are active or not. 
            - Memory usage stats in the sandbox are only approximate.
            - Sentry maintains an internal breakdown of memory usage, and can collect accurate information but only through a relatively expensive API call.
        - Host may reclaim or swap pages without Sentry knowing.
            - considered unwise to share precise information about how the host is managing memory with the sandbox
        - When an application marks memory as no longer uses, Sentry immediately releases memory back to host.
            - allows the host to more effectively multiplex resources and apply an efficient global policy
            - There can be performance penalties for this, since it may be cheaper in many cases to retain the memory and use it to satisfy some other request.
- Limits
    - All Sentry threads and Sentry memory are subject to a container cgroup.
    - Application memory use is accounted to the `memfs`.
    - Anonymous memory corresponds to Sentry usage.
    - Host memory charged to the container works as standard.
    - The cgroups can be monitored for standard signals: pressure indicators, threshold notifiers, etc. and can also be adjusted dynamically.
    - Sentry has the ability to monitor its own cgroup and purge internal caches.


## Will Daughtridge



