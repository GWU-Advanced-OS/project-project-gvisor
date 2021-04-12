## Jack Umina



## Jake Cannizzaro



## Jon Terry
* Sentry requests memory from host in 16MB chunks to minimize mmap calls and improve performance for large allocations
* Included option to use host networking instead of gvisor networking with sentry netstack to improve performance
* files opened by gopher initially opened as readonly by default for performance
    * "The reason that the file is not opened initially as read-write is for better performance with 'overlay2' storage driver. overlay2 eagerly copies the entire file up when it's opened in write mode, and would perform badly when multiple files are only being opened for read (esp. startup)." (code comments)


## Sam Frey



## Will Daughtridge



