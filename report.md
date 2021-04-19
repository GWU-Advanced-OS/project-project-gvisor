# gVisor Report

## Intro (summary, core domain)
gVisor is a container sandboxer that aims to provide highly isolated environments in which to execute less than fully trusted applications while solving a multitude of problems and inaptitudes inherent to containers and sandboxing with virtual machines. 

In recognition of the gaps in isolation resulting from all containers sharing a single host operating system and all VMs sharing a hypervisor, gVisor provides a user-level implementation of Linux - the Sentry. This user-level application provides the system API to containerized applications while preventing any untrusted application from directly interacting with the host OS. Providing each sandbox with its own independent Sentry prevents untrusted applications from escaping their isolated environment through direct attacks on the shared hypervisor that are possible with traditional sandboxes. While the Sentry implements the Linux system API, the API exposed to guest applications is not identical to that of Linux. Confines are imposed on the set of system calls available to both guest applications and the Sentry itself in order to lessen the attack surface on the system. The attack suface is further diminished by relocating file system operations such as ```open()``` to a seperate module Gofer, independent and isolated from the Sentry.

In addition to its security and isolation goals, gVisor is designed with the intent to minimize start up time for containers. This is evidenced by its main deviation from traditional container sandboxing with virtual machines - rather than creating virtualized hardware for a guest kernel that guest applications will interact with, the system API provided by the Sentry is based directly off the host system API with the Sentry deferring to the host at runtime for some services.

In relation to alternatives to gVisor for isolating less than fully trusted applications for execution on a shared system such as traditional linux containers, gVisor suffers from dreadful performance. The performance hits to gVisor directly result from the exact features of the system that provide the security, isolation, and defense in depth it was built for. While the performance of gVisor lacks in relation to traditional containers, it is optimized for efficient building and destroying of containers and achieves better performance in this than container sandboxes implemented via virtualized hardware and a guest kernel. 

The poor performance of gVisor in memory usage, networking, I/O and more make this system not well suited for extensive applications that execute for longer periods of time and necessitate abuntant resources. gVisor is best suited for serverless frameworks leveraging Function as a Service where applications will be run for short periods of time to provide a service, then are destroyed. The ability of gVisor to quickly build and destroy containers furthers the suitability of the system for serverless frameworks as this infrastructure necessitates multiple instantiations of these containers to execute services for many clients. Clearly minimizing construction and deconstruction time of containers maximizes the effiency and productivity of the service provider.

 Function as a Service has become more prevelent in recent years and cloud computing has grown - gVisor provides the requisite security principles and depth for the execution of untrusted guest applications from a myriad of clients in cloud computation, and is optimized for the Function as a Service model frequently implemented in modern cloud computing. As a result of these core features of gVisor, it is highly suitable and immensely valuable in cloud computing while the performance tradeoffs of these core features make gVisor a poor fit for just about any other purpose or environment.
## Modules (Sentry, Gofer, runsc, platforms)
.
## Abstractions (and code examples showing implementation with type defs)

## Security

### Overview
To acheive the wanted level of security and separation, gVisor deploys a few different tactics. Firstly, gVisor ensures that the sandboxed application does not give system calls directly to the host. How is this done? The sentry 'processes' all made system calls from the sandboxed application that are redirected over by ptrace or the KVM (more on that later). Once the sentry receives the redirected system call, it may *not* need to actually communicate with the host. *If* it does, however, it will need to switch out of user-mode to kernel-mode to make the necessary call to the host. But do not fear, the layers don't stop there! The sentry has its own implementation of all whitelisted system calls - the sentry only is allowed a subset of all possible system calls. The sentry has its own user-level networking stack implemented for communication with the host. Like mentioned previously, if the sentry does indeed need to make a system call out to the host, it does it through the netstack. If requested, the sentry can also utilize the host's networking stack implementation in passthrough. Lastly, the sentry has its own file system gopher process, aptly named Gofer. The sentry communicates with Gofer via the 9P protocol.   


**The following following diagram illustrates a few key concepts:**
1. The redirection of system calls that are made by the sandboxed application to the sentry
2. The limited set of system calls that the Sentry actually has access to
3. The passing off to Gofer via the 9P protocol

![image info](./assets/fig1.png)


**A simple illustration of the user-level networking stack:**

![image info](./assets/fig2.png)


### Syscalls

Let's now look at the syscall-related layer in the security sandwich. When the contained application makes a system call, it needs to be redirected somehow to the Sentry, but how is this acheived? The application threads are traced by the Sentry's ptrace implementation.

**Example of how ptrace attaches a tracer to thread**
```go
// attach attaches to the thread.
func (t *thread) attach() {
	if _, _, errno := syscall.RawSyscall6(syscall.SYS_PTRACE, syscall.PTRACE_ATTACH, uintptr(t.tid), 0, 0, 0, 0); errno != 0 {
		panic(fmt.Sprintf("unable to attach: %v", errno))
	}

	// PTRACE_ATTACH sends SIGSTOP, and wakes the tracee if it was already
	// stopped from the SIGSTOP queued by CLONE_PTRACE (see inner loop of
	// newSubprocess), so we always expect to see signal-delivery-stop with
	// SIGSTOP.
	if sig := t.wait(stopped); sig != syscall.SIGSTOP {
		panic(fmt.Sprintf("wait failed: expected SIGSTOP, got %v", sig))
	}

	// Initialize options.
	t.init()
}
```

**Does the system call need to be intercepted/run in user-level?**
```go
// gvisor/pkg/sentry/kernel/ptrace.go

// ptraceSyscallEnter is called immediately before entering a syscall to check
// if t should enter ptrace syscall-enter-stop.
func (t *Task) ptraceSyscallEnter() (taskRunState, bool) {
	if !t.hasTracer() {
		return nil, false
	}
	t.tg.pidns.owner.mu.RLock()
	defer t.tg.pidns.owner.mu.RUnlock()
	switch t.ptraceSyscallMode {
	case ptraceSyscallNone:
		return nil, false
	case ptraceSyscallIntercept:
		t.Debugf("Entering syscall-enter-stop from PTRACE_SYSCALL") // tracking the syscall
		t.ptraceSyscallStopLocked()
		return (*runSyscallAfterSyscallEnterStop)(nil), true
	case ptraceSyscallEmu:
		t.Debugf("Entering syscall-enter-stop from PTRACE_SYSEMU") // no host system calls for you
		t.ptraceSyscallStopLocked()
		return (*runSyscallAfterSysemuStop)(nil), true
	}
	panic(fmt.Sprintf("Unknown ptraceSyscallMode: %v", t.ptraceSyscallMode))
}

// ...

// gvisor/pkg/sentry/kernel/task_syscall.go

func (t *Task) doSyscallEnter(sysno uintptr, args arch.SyscallArguments) taskRunState {
	if next, ok := t.ptraceSyscallEnter(); ok { // this means that either a) it needs to be run in user-level, or b) it is being traced
		return next
	}
	return t.doSyscallInvoke(sysno, args) // otherwise, execute!
}
```

**Example ```pipe``` syscall implemented in Sentry**
```go
// pipe2 implements the actual system call with flags.
func pipe2(t *kernel.Task, addr hostarch.Addr, flags uint) (uintptr, error) {
	if flags&^(linux.O_NONBLOCK|linux.O_CLOEXEC) != 0 {
		return 0, syserror.EINVAL
	}
	r, w := pipe.NewConnectedPipe(t, pipe.DefaultPipeSize)

	r.SetFlags(linuxToFlags(flags).Settable())
	defer r.DecRef(t)

	w.SetFlags(linuxToFlags(flags).Settable())
	defer w.DecRef(t)

	fds, err := t.NewFDs(0, []*fs.File{r, w}, kernel.FDFlags{
		CloseOnExec: flags&linux.O_CLOEXEC != 0,
	})
	if err != nil {
		return 0, err
	}

	if _, err := primitive.CopyInt32SliceOut(t, addr, fds); err != nil {
		for _, fd := range fds {
			if file, _ := t.FDTable().Remove(t, fd); file != nil {
				file.DecRef(t)
			}
		}
		return 0, err
	}
	return 0, nil
}
```



## Performance / Optimizations

In looking at the performance of gVisor, it is important to look at five main benchmarks:
1. Container startup/tear down
2. System call throughput
3. Memory allocation
4. File system access
5. Networking 

An important point that must be discussed before comparing the performance of gVisor is which platform is used to handle system calls made to the host. The first is *Kernel Virtual Mode (KVM)* which allows Linux itself to act as hypervisor by providing a loadable kernel module. The other option is *ptrace* which allows a process to intercept a system call being called.
It should be noted that ptrace [suffers from the highest structural costs by far](https://gvisor.dev/docs/architecture_guide/performance/).

### The True Cost of Contanerization - Ethan G. Young, et al.

A [paper written by Ethan G. Young, et al. at the Univeristy of Wisconsin](/research/performance-res/true-cost-containing-young.pdf) ran experiments running runc against runsc in both ptrace and KVM mode. Their study examined the two systems in the five different benchmarks discussed previously.

#### Container Startup/Tear Down

![Container Startup/Tear Down Results](/research/performance-res/young-cont-init.png)

The results suggest that the differences between running gVisor with ptrace versus KVM for container initialization is neglible. In the context of runc however, there is about a 13% decrease in performance between runc and runsc. Although Google claims that gVisor is designed use in machines with many containers, these results suggest that runc still has an edge here.

#### System Call Throughput

In order to test the system call performace of gVisor, three versions of the same `gettimeofday` syscall was implemented: one invoking just the Sentry, one invoking the host OS, and the third invoking the use of Gofer. It is also important to note that gVisor was tested in both ptrace and KVM mode.

![System Call Throughput Results](/research/performance-res/young-syscall.png)

The implication here is that even in gVisor's best case (running in KVM and only calling Sentry), the performance is still 2.8x slower. It is also clear from the results that calling to Gofer suffers from the worst performance. Compared to runc, Gofer runs between 156x and 175x slower depeding on the platform.

#### Memory Allocation

![Memory Allocation Results](/research/performance-res/young-malloc.png)

The key takeaway from these results is that gVisor achieves just 40% the allocation rate of native systems.

#### File System Access

![File System Access Results](/research/performance-res/young-file-access.png)

As previously discussed, Gofer suffers from the largest performance tradeoff. This is even more evident in the results of using Gofer to access files. Opening and closing files on Gofer's external tmpfs is 216x slower than native compared to just 12x slower for access to Sentry's internal tmpfs.

#### Networking

gVisor uses its own network stack in order to safely and securely handle all networking down. This is one area in particular that [Google claims "is improving quickly"](https://gvisor.dev/docs/architecture_guide/performance/#network).
To test networking throughput, `wget` was called for file sizes of various sizes.

![Networking Results](/research/performance-res/young-network.png)

The results show that gVisor may handle small downloads well, relative to native performance, but as file sizes increase, gVisor fails to scale well.

### Security-Performance Trade-offs of Kubernetes Container Runtimes - Viktorsson, et al.

Another [study](/research/performance-res/security-performace-tradeoffs-viktorsson.pdf) attempted to measure the performace of gVisor in more real world applications rather. All tests run in this study used the pTrace platform.
Three different application's total throughput were tested:

1. **TeaStore:**

- TeaStore is a microservice benchmark that emulates a webstore and provides features that include browising, selecting, and ordering tea. The throughput is measured as the average requests per second throughput for eight available API operations.

2. **Redis:**
- Redis is an in memory data-store featuring data structures such as hashes, lists, sets, and more. The throughput is measure using requests per second of the O(1) GET operation.

3. **Spark:**
 - Spark is a distributed general purpose computing framework for big data processing. The throughput is measured as the average number of primes found per second when finding all prime numbers in the first million integers.

![Teastore-Redis-Spark Results](/research/performance-res/redis-spark-teastore-experiment.png)

In testing TeaStore and Spark, gVisor has about 40-60% the throughput of runc. For Redis, it suffers dramtically at just 20% the throughput of runc. The poor performace in Redis is likely due to the fact that it is neither CPU nor memory demanding and thus its performance is based solely on the GET request to in-memory data. This suggests that Redis performance is largely based on networking throughput.

## Subjective Opinions
- Sam
- Jake
- Jack
- Will
- Jon
