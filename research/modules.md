## Jack Umina



## Jake Cannizzaro



## Jon Terry



## Sam Frey
#### [What is gVisor](https://gvisor.dev/docs/)
- runsc executable
    - implements [Open Container Initiative (OCI)](https://www.opencontainers.org/) runtime spec
        - Also used by Docker and Kubernetes
    - Capable of running any OCI compatible bundle
        - OCI bundle includes container config JSON file and a root filesystem for the container
    - entry point to container
    - Implements commands for starting, stopping, listing, and querying the status of containers.

- Sentry
    - Largest component
    - Acts as application kernel
    - Implements sys calls, signal delivery, memory management, page faulting, threading
    - Does not pass system calls to the host kernel
        - sentry may make its own system calls to the host kernel to support its operation.
    - Makes calls to Gofer for any file outside the sandbox
        - Sentry can access sandbox-internal files like ```/proc``` and pipes directly
- Gofer
    - Host process started for each container
    - Communicates with sentry using 9P over socket or shared memory
    - Handles all file system resource requests that reach beyond the container
- Platform
    - KVM or ptrace
    - redirects system calls to sentry
    - see ```abstractions.md```
- Application
    - a standard Linux binary


## Will Daughtridge



