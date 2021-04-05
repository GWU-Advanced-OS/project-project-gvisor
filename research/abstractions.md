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


## Will Daughtridge



