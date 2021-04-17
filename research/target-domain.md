## Jack Umina



## Jake Cannizzaro

What is gVisor?

> gVisor is a container sandboxer. gVisor is an userspace kernel that implements the Linux system call interface, providing isolation between applications running in a container and the host operating system. gVisor is built to be able to integrate with popular container programs such as Docker and Kubernetes easily. Its sandbox provides more isolation/security than just running them normally (without gVisor).

Why gVisor vs. other container managers or VMs?

> gVisor provides a great deal more isolation than running a program in a standard container. With its userspace kernel implementation, there is isolation between the container and the real host kernel. This helps to protect against privilege escalation, kernel tampering, and more. See [the section on security](security.md). gVisor is also very light weight, with an average 15MB overhead. This is small when compared to a virtual machine.
>
> Existing sandboxing techniques for containers:
>
> Machine-level virtualization:
>
> * Create virtual hardware for a guest kernel and let the guest access it with a VMM.
> * Large footprint, slow start up times
>
> Rule-based execution:
>
> * such as seccomp and SELinux
> * Allows finegrain security policies for the container. This could be blacklisting or whitelisting system calls. These policies are enforced with hooks in the kernel (using BPF or eBPF something similar).
> * Requires analysis of the running program/container because it is near impossible to know what system calls will be made without first running it. This means you can't trust just any unknown app to run.

sources:

* https://www.youtube.com/watch?v=kxUZ4lVFuVo
* https://gvisor.dev/docs/

As cloud computing has become the industry standard for project infrastructure, deployment models like FaaS (functions as a service) are becoming increasingly prevalent. There are multiple aspects to take into mind when considering the trade-offs of the architecture design for these various runtimes which make these services possible. The industry standard and predominantly default OCI runtime is runc. gVisor is the highly secure alternative. gVisor's OCI runtime, runsc, trades security for performance (see [performance](performance.md) for more specific performance evaluations). The ideal usage for gVisor is for small, system call light, applications with a need for high security.

https://www.researchgate.net/profile/Anshul-Jindal-2/publication/341483813_Performance_Evaluation_of_Container_Runtimes/links/5fd0085792851c00f85f1de9/Performance-Evaluation-of-Container-Runtimes.pdf

## Jon Terry



## Sam Frey
#### [What is gVisor](https://gvisor.dev/docs/)
- Efficient, secure container execution
    - Provides a virtualized environment to sandbox containers.
    - Each sandbox gets its own application kernel to catch container escape exploits.
    - Compatible with both Docker and Kubernetes


## Will Daughtridge
