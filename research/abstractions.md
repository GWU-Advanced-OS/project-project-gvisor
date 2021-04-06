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


## Will Daughtridge



