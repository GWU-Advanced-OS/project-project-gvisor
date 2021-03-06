## Hypotheses

#### Target Domain / Use Cases (True)
- Container sandbox that provides additional isolation compared to standard containers.
- Provides a user space kernel for syscalls from the container.
- Best suited to small, serverless-based job execution.

#### Modules
- runsc executable: Entrypoint to running a sandboxed container. Also provides container management commands. (true)

- Sentry: Main source of security. User space kernel. Intercepts all systems calls, makes system calls to the host when necessary, and makes ```open``` and ```close``` file system requests to Gofer. (False)
    - Platform (ptrace or kvm) intercepts calls, seccomp blocks/filters calls that aren't allowed, Sentry implements them

- Gofer: Handles all file system resource requests that reach beyond the container. Provides handles to Sentry to be used for ```read``` and ```write``` calls. (True)
    - Gofer itself is sandboxed. Isolated from both host and container. Each gVisor sandbox gets its own Gofer.

- Application: a standard linux binary.

#### Security
- seccomp whitelists 55 syscalls for Sentry; restricts applications to 211 of 300+ syscalls. Sentry implements those 211 calls using just its 55 allowed calls. (True)

- Sentry doesn't pass system calls directly to the host kernel from user application in sandbox. (true)

- Other than system calls made to the host by Sentry, the sandbox runs exclusively in user level. (true)

- Does not directly protect against hardware exploits. Has to rely on host. (needs further research)

- Each sandbox has its own network stack separate from the host. (true)

- Smaller attack surface than a full VM, but more isolation than a standard container. (subjective, true)

- Gofer mediates all access to sandbox-external file system resources and separates the Sentry from the file system. (true)

- Sentry transparently whitelists capabilities for procs within the sandbox. (True)

#### Performance (relative to Linux?) (true)
- Faster to build and destroy small containers for lightweight applications deployed on demand.

- Otherwise, uttely terrible, and in some cases, atrocious.
    - Gofer up to 216x slower than a standard file op.
    - Syscalls from Sentry to host kernel is up to 9x slower than a standard syscall.

- Networking scales poorly; best suited to smaller requests.