## Jack Umina



## Jake Cannizzaro



## Jon Terry



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