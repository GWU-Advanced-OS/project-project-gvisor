# In what conditions is the performance of the system "good" and in which is it "bad"? How does its performance compare to a Linux baseline (this discussion can be quantitative or qualitative)?

## Jack Umina

### Memory Allocation Stack Trace 

#### From Host to Sentry

Sentry requests large chunks of memory from the host OS and zeros out the mem. This is not immediately made available to the applications running in gvisor, rather, Sentry holds on to the memory and later divides it further when requested by an applicaton.

``` go
// Line 381 of pgalloc.go
// Allocate returns a range of initially-zeroed pages of the given length with
// the given accounting kind and a single reference held by the caller. When
// the last reference on an allocated page is released, ownership of the page
// is returned to the MemoryFile, allowing it to be returned by a future call
// to Allocate.
//
// Preconditions: length must be page-aligned and non-zero.
func (f *MemoryFile) Allocate(length uint64, kind usage.MemoryKind) (memmap.FileRange, error) {

    // ...

    // Align hugepage-and-larger allocations on hugepage boundaries to try
    // to take advantage of hugetmpfs.
    alignment := uint64(hostarch.PageSize)
    if length >= hostarch.HugePageSize {
        alignment = hostarch.HugePageSize
    }

    // Find a range in the underlying file.
    fr, ok := findAvailableRange(&f.usage, f.fileSize, length, alignment)
    if !ok {
        return memmap.FileRange{}, syserror.ENOMEM
    }

    // ...

    if f.opts.ManualZeroing {
        if err := f.manuallyZero(fr); err != nil {
            return memmap.FileRange{}, err
        }
    }
    // Mark selected pages as in use.
    if !f.usage.Add(fr, usageInfo{
        kind: kind,
        refs: 1,
    }) {
        panic(fmt.Sprintf("allocating %v: failed to insert into usage set:\n%v", fr, &f.usage))
    }

    return fr, nil
}
```

``` go
// Line 441 of pgalloc.go
// findAvailableRange returns an available range in the usageSet.
//
// Note that scanning for available slots takes place from end first backwards,
// then forwards. This heuristic has important consequence for how sequential
// mappings can be merged in the host VMAs, given that addresses for both
// application and sentry mappings are allocated top-down (from higher to
// lower addresses). The file is also grown expoentially in order to create
// space for mappings to be allocated downwards.
//
// Precondition: alignment must be a power of 2.
func findAvailableRange(usage *usageSet, fileSize int64, length, alignment uint64) (memmap.FileRange, bool) {
    alignmentMask := alignment - 1

    // Search for space in existing gaps, starting at the current end of the
    // file and working backward.
    lastGap := usage.LastGap()
    gap := lastGap
    for {
        end := gap.End()
        if end > uint64(fileSize) {
            end = uint64(fileSize)
        }

        // Try to allocate from the end of this gap, with the start of the
        // allocated range aligned down to alignment.
        unalignedStart := end - length
        if unalignedStart > end {
            // Negative overflow: this and all preceding gaps are too small to
            // accommodate length.
            break
        }
        if start := unalignedStart &^ alignmentMask; start >= gap.Start() {
            return memmap.FileRange{start, start + length}, true
        }

        gap = gap.PrevLargeEnoughGap(length)
        if !gap.Ok() {
            break
        }
    }

    // Check that it's possible to fit this allocation at the end of a file of any size.
    min := lastGap.Start()
    min = (min + alignmentMask) &^ alignmentMask
    if min+length < min {
        // Overflow: allocation would exceed the range of uint64.
        return memmap.FileRange{}, false
    }

    // ...
}
```

#### From Sentry to Application

When an application running in gVisor calls `mmap()`, first the `Mmap()` syscall is invoked:
``` go
// Line 42 of sys_mmap.go
func Mmap(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error)
```
- `t` is a Task that represents an execution thread in an un-trusted app
  - This includes registers and any thread-specific state
- `SyscallArguments` include the length of the memory region requested and a pointer to the memory
  - These arguments get stored in a `MMapOpts` object

From here, `MMap()` is invoked in Sentry.

``` go
// Line 75 of syscalls.go
func (mm *MemoryManager) MMap(ctx context.Context, opts memmap.MMapOpts) (hostarch.Addr, error) {
```
- Takes in a `Context` and `MMapOpts` as arguments
  - `Context` is the execution thread that called mmap  

Inside of `MMap()`, `createVMALocked` is called on line 122 which is where a new memory region is actually created.

``` go
// Line 33 of vma.go
func (mm *MemoryManager) createVMALocked(ctx context.Context, opts memmap.MMapOpts) (vmaIterator, hostarch.AddrRange, error) {

    // ...
    // Line 38

    // Find a usable range.
    addr, err := mm.findAvailableLocked(opts.Length, findAvailableOpts{
        Addr:     opts.Addr,
        Fixed:    opts.Fixed,
        Unmap:    opts.Unmap,
        Map32Bit: opts.Map32Bit,
    })

    // ...
    // Line 55    

    // Check against RLIMIT_AS.
    newUsageAS := mm.usageAS + opts.Length
    if opts.Unmap {
        newUsageAS -= uint64(mm.vmas.SpanRange(ar))
    }
    if limitAS := limits.FromContext(ctx).Get(limits.AS).Cur; newUsageAS > limitAS {
        return vmaIterator{}, hostarch.AddrRange{}, syserror.ENOMEM
    }

    if opts.MLockMode != memmap.MLockNone {
        // Check against RLIMIT_MEMLOCK.
        if creds := auth.CredentialsFromContext(ctx); !creds.HasCapabilityIn(linux.CAP_IPC_LOCK, creds.UserNamespace.Root()) {
            mlockLimit := limits.FromContext(ctx).Get(limits.MemoryLocked).Cur
            if mlockLimit == 0 {
                return vmaIterator{}, hostarch.AddrRange{}, syserror.EPERM
            }
            newLockedAS := mm.lockedAS + opts.Length
            if opts.Unmap {
                newLockedAS -= mm.mlockedBytesRangeLocked(ar)
            }
            if newLockedAS > mlockLimit {
                return vmaIterator{}, hostarch.AddrRange{}, syserror.EAGAIN
            }
        }
    }

    // ...
}
```
- Again takes a `Context` and the same `MMapOpts` as parameters
- Finds a mappable region of memory to allocate
- Checks the permissions of the `Context` to see if it can access this region and can allocate more memory
- Creates the VMA
- Returns the address to the region


#### Tradeoffs of gVisor's Memory Allocation
Due to the double level page table system, applications requesting small pieces of memory (relative to the size requested from the host by Sentry) suffer in performace. As the size of the memory requested by an application increases, the performance increases. However, it should be noted that memory allocation of any size is not very fast in gvisor relative native Linux containers.
*See studies below quantifying this performance*


[The True Cost of Containing: A gVisor Case Study - Young](https://github.com/GWU-Advanced-OS/project-project-gvisor/blob/main/research/performance-res/true-cost-containing-young.pdf)

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

[gVisor.dev](https://gvisor.dev/docs/architecture_guide/)

#### Memory Overhead 
- No additional memory overhead for raw accesses once initial mappings are installed through Sentry
- Sentry uses a small, fixed amount of memory to track state of the application

#### Memory Allocation
- "In order to avoid excessive overhead, the Sentry does not demand-page individual pages. Instead, it selects appropriate regions based on heuristics. There is a trade-off here: the Sentry is unable to trivially determine which pages are active and which are not. Even if pages were individually faulted, the host may select pages to be reclaimed or swapped without the Sentry’s knowledge."
- Sentry implements a two level page table system
- First, a large region is requested from the host which is later sliced into smaller pieces to be used by applications inside the sandbox

[Security-Performance Trade-offs of Kubernetes Container Runtimes - Viktorsson](https://github.com/GWU-Advanced-OS/project-project-gvisor/blob/main/research/performance-res/security-performace-tradeoffs-viktorsson.pdf)

### Performance Experiment between Redis, Spark, and TeaStore

Experiment was conducted using gVisor running on pTrace.

#### Applications Tested

1. **TeaStore:**
 - Microservice bencmark that emulates a web store.
 - Includes features such as browsing, selecting, and ordering tea.
 - *Throughput* measured based on average requests per second using a mix of the eight different API operations.
2. **Redis**
 - "An in memory data-store featuring data structures such as hashes, lists, sets, and more."
 - *Throughput* measured using request per second of the O(1) GET operation.
3. **Spark**
 - "A distributed general purpose computing framework for big data processing."
 - *Throughput* measured as the average amount of primes found per second when finding all prime numbers in the first million numbers.

#### Results

##### Deployment Time (gVisor compared to runc)
- **TeaStore:** About 3 times longer
- **Spark** About 3 times longer
- **Redis** Almost twice as long

##### Throughput (gVisor compared to runc)
- **TeaStore:** About 40-60% throughput of runc
- **Spark** About 40-60% throughput of runc
- **Redis** About 20% throughput of runc
  - Redis score is based on a simple GET request which is neither CPU nor memory demanding and rather networking intensive. gVisor struggles with networking as its netstack still requires significant developement.

##### Overhead
- gVisor imposes a 14 MB memory overhead compared to runc

[Blending Containers and Virtual Machines: A Study of Firecracker and gVisor - Anjali](https://github.com/GWU-Advanced-OS/project-project-gvisor/blob/main/research/performance-res/blending-containers-vms-anjali.pdf)

#### Experiment Setup
- Tests performace across four configurations: host Linux with no isolation, Linux containers (LXC), and gVisor (using KVM-mode)

#### Memory Allocation
- Sentry in gVisor uses a two-level page table
- **Calls to** `do_mmap()` **function in** `mm/mmap.c`:
  - gVisor: 5,382 times
  - LXC: more than 1 million times
- Seems like Sentry makes mmap calls down to kernel for large chunks of memory and then Senty breaks these chunks into smaller pieces. *(TODO: Find code to substantiate claim)*
- **Memory allocation comparison:**
  - Time compared for making succesive mmap calls and unmap calls of varying sizes for a total of 1GB
  - 4KB pieces: gVisor is about 16 times slower
  - 64KB pieces: gVisor is about 8-10 times slower
  - Gap between gVisor closes as mmap size increases, likely due to Senty two-level page table

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



