## Jack Umina



## Jake Cannizzaro



## Jon Terry
* utilizes much of host kernel for networking despite having its own netstack specifically because they wanted to isolate networking from the host OS
    * "Despite having an in-Sentry networking stack (including TCP, UDP,IP4, IP6 and ICMP), gVisor has the highest overall coverage and surprisingly exercises much 
		of the same code as LXC under/net." (1)
* executes pretty much the same host OS kernel code as Linux Containers despite having its own implementation of the OS
    * "The code coverage analysis shows that despite moving much operating system functionality out of the kernel,
		both gVisor and Firecracker execute substantially more Linux kernel code than native Linux alone, and that 
		much of the code executed is not in different functions,but rather conditional code within the same functions executed by native Linux." (1)
* seccomp filters installed to control what system calls can be made - kills process if invalid call is made
    * "Install generates BPF code based on the set of syscalls provided. It only allows syscalls that conform to the specification. Syscalls that violate the specification will trigger RET_KILL_PROCESS" (code comments)


(1): Ending Containers and Virtual Machines: A Study of Firecracker and gVisor - Anjali, Caraza-Harter, Swift


## Sam Frey



## Will Daughtridge

https://gvisor.dev/docs/architecture_guide/security/

### exposure
* layered defense to protect against system API exploits
    * still need to provide process model
    * the 'Sentry' intercepts direct communication b/w app and system API
    * Sentry implements the system API instead of app directly using system API
    * Sentry is exposed to a reduced system API it can use itself
    * fights direct and indirect exploits
    * like a VM's method of indirection
    * unlike a VM, the Sentry implements a system API directly from the host's system API, and there is no virtualization in between

### sandbox
* applications can do *most* things, but there are some gotchas
    * e.g. an application will not be able to manipulate underlying host resources
    * sandbox has limited comms with the host. they are the following:
        * 'Gofer' process (TODO: define Gofer process)
        * reduced set of host system call capability
        * r/w packets to virtualized ethernet

### system ABI and side channels and other vectors, oh my!
* reliance on host for protection against exploits of hardware
    * gVisor can't do much to help directly, but virtualization, encryption, etc. can indirectly
* reliance on host for protection against DoS, resource exhaustion
    * nature of being in the sandbox assists in deterring these attacks

### overlying principles
* You shall not pass!
    * Gandalf ..whoops, I mean.. the Sentry does not allow for direct passage of system calls to the host
    * the Sentry individually implements host system calls
        * drawback = have to implement everything in Sentry   
* no specialized APIs
    * APIs exposed in the host for specialized uses do not need to be implemented in the Sentry
    * only the necessary APIs are implemented
* reduce surface that the Sentry is exposed to for host
    * no opening of new files, creating new sockets, and other things
* unsafe code is located in "unsafe.go" files
    * only unsafe can import unsafe
* must be pure Go
    * no CGo
* generally no external importing in core pkgs
    * utmost control is needed for security

### example creation of net stack for sentry
```go
// NewTestStack returns a TestStack with no network interfaces. The value of
// all other options is unspecified; tests that rely on specific values must
// set them explicitly.
func NewTestStack() *TestStack {
	return &TestStack{
		InterfacesMap:     make(map[int32]Interface),
		InterfaceAddrsMap: make(map[int32][]InterfaceAddr),
	}
}
+
```

### doSyscall - entry point for user app made syscalls
```go
// doSyscall is the entry point for an invocation of a system call specified by
// the current state of t's registers.
//
// The syscall path is very hot; avoid defer.
func (t *Task) doSyscall() taskRunState {
	// Save value of the register which is clobbered in the following
	// t.Arch().SetReturn(-ENOSYS) operation. This is dedicated to arm64.
	//
	// On x86, register rax was shared by syscall number and return
	// value, and at the entry of the syscall handler, the rax was
	// saved to regs.orig_rax which was exposed to userspace.
	// But on arm64, syscall number was passed through X8, and the X0
	// was shared by the first syscall argument and return value. The
	// X0 was saved to regs.orig_x0 which was not exposed to userspace.
	// So we have to do the same operation here to save the X0 value
	// into the task context.
	t.Arch().SyscallSaveOrig()

	sysno := t.Arch().SyscallNo()
	args := t.Arch().SyscallArgs()

	// Tracers expect to see this between when the task traps into the kernel
	// to perform a syscall and when the syscall is actually invoked.
	// This useless-looking temporary is needed because Go.
	tmp := uintptr(unix.ENOSYS)
	t.Arch().SetReturn(-tmp)

	// Check seccomp filters. The nil check is for performance (as seccomp use
	// is rare), not needed for correctness.
	if t.syscallFilters.Load() != nil {
		switch r := t.checkSeccompSyscall(int32(sysno), args, hostarch.Addr(t.Arch().IP())); r {
		case linux.SECCOMP_RET_ERRNO, linux.SECCOMP_RET_TRAP:
			t.Debugf("Syscall %d: denied by seccomp", sysno)
			return (*runSyscallExit)(nil)
		case linux.SECCOMP_RET_ALLOW:
			// ok
		case linux.SECCOMP_RET_KILL_THREAD:
			t.Debugf("Syscall %d: killed by seccomp", sysno)
			t.PrepareExit(ExitStatus{Signo: int(linux.SIGSYS)})
			return (*runExit)(nil)
		case linux.SECCOMP_RET_TRACE:
			t.Debugf("Syscall %d: stopping for PTRACE_EVENT_SECCOMP", sysno)
			return (*runSyscallAfterPtraceEventSeccomp)(nil)
		default:
			panic(fmt.Sprintf("Unknown seccomp result %d", r))
		}
	}

	return t.doSyscallEnter(sysno, args)
}
```

### interesting discussion about sentry intercepting syscalls
* https://groups.google.com/g/gvisor-users/c/15FfcCilupo/m/9ARSLnH3BQAJ
* sentry can run in ring0 and ring3

### diagram for syscall flow from app
https://github.com/google/gvisor/blob/master/pkg/sentry/kernel/g3doc/run_states.png

### architecture diagram
* following picture displays sentry as intermediary layer between application and host kernel
https://github.com/google/gvisor/blob/master/g3doc/Sentry-Gofer.png

### example linux syscall (pipe) implemented in sentry
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

### sentry checking for capabilities, and not exposing to an application if they don't
```go
// CapError gives a syscall function that checks for capability c.  If the task
// has the capability, it returns ENOSYS, otherwise EPERM. To unprivileged
// tasks, it will seem like there is an implementation.
func CapError(name string, c linux.Capability, note string, urls []string) kernel.Syscall {
	if note != "" {
		note = note + "; "
	}
	return kernel.Syscall{
		Name: name,
		Fn: func(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
			if !t.HasCapability(c) {
				return 0, nil, syserror.EPERM
			}
			t.Kernel().EmitUnimplementedEvent(t)
			return 0, nil, syserror.ENOSYS
		},
		SupportLevel: kernel.SupportUnimplemented,
		Note:         fmt.Sprintf("%sReturns %q if the process does not have %s; %q otherwise.", note, syserror.EPERM, c.String(), syserror.ENOSYS),
		URLs:         urls,
	}
}
```

### watchdog code implementation
```go
// runTurn runs a single pass over all tasks and reports anything it finds.
func (w *Watchdog) runTurn() {
	// Someone needs to watch the watchdog. The call below can get stuck if there
	// is a deadlock affecting root's PID namespace mutex. Run it in a goroutine
	// and report if it takes too long to return.
	var tasks []*kernel.Task
	done := make(chan struct{})
	go func() { // S/R-SAFE: watchdog is stopped and restarted during S/R.
		tasks = w.k.TaskSet().Root.Tasks()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(w.TaskTimeout):
		// Report if the watchdog is not making progress.
		// No one is watching the watchdog watcher though.
		w.reportStuckWatchdog()
		<-done
	}

	newOffenders := make(map[*kernel.Task]*offender)
	newTaskFound := false
	now := ktime.FromNanoseconds(int64(w.k.CPUClockNow() * uint64(linux.ClockTick)))

	// The process may be running with low CPU limit making tasks appear stuck because
	// are starved of CPU cycles. An estimate is that Tasks could have been starved
	// since the last time the watchdog run. If the watchdog detects that scheduling
	// is off, it will discount the entire duration since last run from 'lastUpdateTime'.
	discount := time.Duration(0)
	if now.Sub(w.lastRun.Add(w.period)) > descheduleThreshold {
		discount = now.Sub(w.lastRun)
	}
	w.lastRun = now

	log.Infof("Watchdog starting loop, tasks: %d, discount: %v", len(tasks), discount)
	for _, t := range tasks {
		tsched := t.TaskGoroutineSchedInfo()

		// An offender is a task running inside the kernel for longer than the specified timeout.
		if tsched.State == kernel.TaskGoroutineRunningSys {
			lastUpdateTime := ktime.FromNanoseconds(int64(tsched.Timestamp * uint64(linux.ClockTick)))
			elapsed := now.Sub(lastUpdateTime) - discount
			if elapsed > w.TaskTimeout {
				tc, ok := w.offenders[t]
				if !ok {
					// New stuck task detected.
					//
					// Note that tasks blocked doing IO may be considered stuck in kernel,
					// unless they are surrounded b
					// Task.UninterruptibleSleepStart/Finish.
					tc = &offender{lastUpdateTime: lastUpdateTime}
					stuckTasks.Increment()
					newTaskFound = true
				}
				newOffenders[t] = tc
			}
		}
	}
	if len(newOffenders) > 0 {
		w.report(newOffenders, newTaskFound, now)
	}

	// Remember which tasks have been reported.
	w.offenders = newOffenders
}

// report takes appropriate action when a stuck task is detected.
func (w *Watchdog) report(offenders map[*kernel.Task]*offender, newTaskFound bool, now ktime.Time) {
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("Sentry detected %d stuck task(s):\n", len(offenders)))
	for t, o := range offenders {
		tid := w.k.TaskSet().Root.IDOfTask(t)
		buf.WriteString(fmt.Sprintf("\tTask tid: %v (goroutine %d), entered RunSys state %v ago.\n", tid, t.GoroutineID(), now.Sub(o.lastUpdateTime)))
	}
	buf.WriteString("Search for 'goroutine <id>' in the stack dump to find the offending goroutine(s)")

	// Force stack dump only if a new task is detected.
	w.doAction(w.TaskTimeoutAction, newTaskFound, &buf)
}
```

```go

```