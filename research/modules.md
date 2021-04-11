## Jack Umina



## Jake Cannizzaro
#### Isolation boundaries, filesystem resources, & the Gofer module:
Gofer is a file proxy that runs as a separate process, isolated from the sandbox, giving access to file system resources. A separate gofer instance runs for each running sandbox instance. They communicate with their respective sentrys using the 9p protocol.
Host filesystem is isolated from the sandbox using an overlay file system. This creates a temporary union mount filesystem. Thus all changes made to files are stored within the sandbox but do not affect the host file system.
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
This will allow the container to use the fs outside the root of the sandbox but not the other way around. If one needs more than one instance to have access to the directory, a shared command can be used to allow access from outside the container. This is done by adding `"--file-access=shared"` to the `runtimeArgs` section shown above.

#### Diving in to the code:
Starting at `gvisor/runsc/cmd/gofer.go` ---
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
