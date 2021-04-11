# In what conditions is the performance of the system "good" and in which is it "bad"? How does its performance compare to a Linux baseline (this discussion can be quantitative or qualitative)?

## Jack Umina

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

[gVisor.dev - Performace Guide](https://gvisor.dev/docs/architecture_guide/performance/)

#### Memory Overhead 
- No additional memory overhead for raw accesses once initial mappings are installed through Sentry
- Sentry uses a small, fixed amount of memory to track state of the application

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

![Results of TeaStore - Redis - Spark Experiment](https://github.com/GWU-Advanced-OS/project-project-gvisor/blob/main/research/performance-res/redis-spark-teastore-experiment.png)

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



