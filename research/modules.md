## Jack Umina



## Jake Cannizzaro
#### Isolation boundaries, filesystem resources, & the Gofer module:
Gofer is a file proxy that runs as a separate process, isolated from the sandbox, giving access to file system resources. A separate gofer instance runs for each running sandbox instance. They communicate with their respective sentrys using the 9p protocol.
The host filesystem is isolated from the sandbox using an overlay file system. This creates a temporary union mount filesystem. Thus all changes made to files are stored within the sandbox but do not affect the host file system.
Instructions to use this overlay filesystem can be found [here](https://gvisor.dev/docs/user_guide/filesystem/):
To use the tmpfs overlay, add the following runtimeArgs to your Docker configuration (/etc/docker/daemon.json) and restart the Docker daemon:
```
{
    "runtimes": {
        "runsc": {
            "path": "/usr/local/bin/runsc",
            "runtimeArgs": [
                "--overlay"
            ]
       }
    }
}
```
This will allow the Gofer process to use the fs outside the root of the sandbox but not the other way around. If one needs more than one instance to have access to the directory, a shared command can be used to allow access from outside the container. This is done by adding `"--file-access=shared"` to the `runtimeArgs` section shown above.

#### Diving in to the [code](https://github.com/google/gvisor):
Starting at [runsc/cmd/gofer.go](https://github.com/google/gvisor/blob/master/runsc/cmd/gofer.go) ---
Gofer uses golang [subcommands](https://github.com/google/subcommands) so that when the program is run, additional arguments can be set to set parameters within the code. These arguments populate the `Gofer` struct.
```
// Gofer implements subcommands.Command for the "gofer" command, which starts a
// filesystem gofer.  This command should not be called directly.
type Gofer struct {
	bundleDir string   //refers to the directory containing the executable code
	ioFDs     intFlags //file descriptors used to communicate with 9p servers
	applyCaps bool     //boolean var sets whether or not capabilities are
                       //used to restrict the Gofer process. Default = true
	setUpRoot bool     //boolean var indicates whether or not an empty root should
                       //set up for the process. Default = true
	specFD   int       //file descriptor pointing to the OCI runtime spec file
	mountsFD int       //mountsFD is the file descriptor to write list of mounts
                       //after they have been resolved (direct paths, no symlinks)
}
```
The main logic of this program begins with `Execute()`. It begins by populating two variables, `conf`, and `spec`. `conf` is an instance of a [config](https://pkg.go.dev/gvisor.dev/gvisor/runsc/config#Config) which holds environment configuration information that isn't a part of the runtime spec. The runtime spec (example [here](https://gist.githubusercontent.com/nl5887/9b26ef8dfa5b7c1247bc09bb46175346/raw/config.json)) is populated into `spec` by calling `specutils.ReadSpecFromFile()` on the file obtained with the `specFD` field of the `Gofer` struct. This method parses through the json spec file and updates the `conf` variable and then returns `spec`. This is important as these will be used throughout the rest of the program.
... maybe above gets too specific...moving on for now...
Setting up the root filesystem:
`func setupRootFS(spec *specs.Spec, conf *config.Config) error {`
This function first turns all shared mounts into slave mounts so that changes can propagate into the shared mounts but not outside of the namespace into the host. This mount command uses the `MS_SLAVE` and `MS_REC` to accomplish this so that every mount under "/" becomes a slave. Next, the root needs to be mounted on a new `tmpfs` filesystem. `runsc` requires a `/proc` directory so it is done here. Under `/proc`, new directories `/proc/proc` and `/proc/root` are created to give a location for the sandbox root. The new `/proc/proc` is mounted with the following flags for to prevent any attempts to break out of the isolated sandbox:
- MS_RDONLY
    - don't allow process to write changes.
- MS_NOSUID
    - don't allow system to use/contain set user id files. This helps to prevent privilege escalation.
- MS_NODEV
    - don't allow access to devices or special files on the filesystem
- MS_NOEXEC
    - don't allow program execution on this filesystem

The Gofer process's root is then mounted on the new `/proc/root` with the source directory specified by the spec file. The following flags are used:
- MS_BIND
    - Bind mount takes an existing filesystem structure and places it in a new location in the file system. This is used to place the Gofer process's directory, which is saved on the host, in an isolated location within the sandbox without copying everything over.
- MS_SLAVE
    - Turns a shared mount point into a slave mount point. This means changes can propagate from the source (the host) but changes made in the slave will not propagate to the source. Any attempts to maliciously delete files will only effect the current running sandboxed process.
- MS_REC
    - Recursively propagate these mount options to all subdirectories of the mount point.

Once the initial filesystem has been created, `setupMounts()` and `resolveSymlinks()` are called to bind all mounts specified in the spec file as well as changing any relative paths and symlinks so that they point to their new locations within the sandbox. Depending on the spec, the new root filesystem can be remounted read only for extra protection. At this point the filesystem is set up but still in some subdirectory of the process's view of the namespace. `pivotRoot()` is called to actually make the newly created root the process's root. After this, the process is sandboxed and cannot access the host filesystem.
After setting up the process's file system, capabilities are set with goferCaps:
```
var caps = []string{
	"CAP_CHOWN",
	"CAP_DAC_OVERRIDE",
	"CAP_DAC_READ_SEARCH",
	"CAP_FOWNER",
	"CAP_FSETID",
	"CAP_SYS_CHROOT",
}

// goferCaps is the minimal set of capabilities needed by the Gofer to operate
// on files.
var goferCaps = &specs.LinuxCapabilities{
	Bounding:  caps,
	Effective: caps,
	Permitted: caps,
}
```
Limiting the process's capabilities to this set bounds the permitted set of capabilities for the process to prevent it from having more privilege than needed. See the [capabilities manual page](https://man7.org/linux/man-pages/man7/capabilities.7.html) to to see just how many capabilities there are in linux and why it makes sense to limit them in this way.


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
