# virtiofsd

A [virtio-fs](https://virtio-fs.gitlab.io/) vhost-user device daemon
written in Rust.

## Building from sources

### Requirements

This project depends on
[libcap-ng](https://people.redhat.com/sgrubb/libcap-ng/) and
[libseccomp](https://github.com/seccomp/libseccomp). You can obtain
those dependencies by building them for their respective sources, or
by installing the correspondent development packages from your
distribution, if available:

- Fedora/CentOS/RHEL
```shell
dnf install libcap-ng-devel libseccomp-devel
```

- Debian/Ubuntu
```shell
apt install libcap-ng-dev libseccomp-dev
```

### Compiling

virtiofsd is written in Rust, so you will have to install [Rust](https://www.rust-lang.org/learn/get-started)
in order to compile it, and it uses [cargo](https://doc.rust-lang.org/cargo/) to manage the
project and its dependencies.
After installing Rust, you can compile it to a binary by running:

```shell
cargo build --release
```

## CI-built binaries

Every time new code is merged, the CI pipeline will upload a debug binary
of virtiofsd. It is intended to be an accessible way for anyone to
download and test virtiofsd without needing a Rust toolchain installed.

The debug binary is built only for x86\_64 Linux-based systems.

[Click here to download the latest build](
https://gitlab.com/virtio-fs/virtiofsd/-/jobs/artifacts/main/download?job=publish)

## Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md)

## Usage
This program must be run as the root user or as a "fake" root inside a
user namespace (see [Running as non-privileged user](#running-as-non-privileged-user)).

The program drops privileges where possible during startup,
although it must be able to create and access files with any uid/gid:

* The ability to invoke syscalls is limited using `seccomp(2)`.
* Linux `capabilities(7)` are dropped. virtiofsd only retains the following capabilities:
`CAP_CHOWN`, `CAP_DAC_OVERRIDE`, `CAP_FOWNER`, `CAP_FSETID`, `CAP_SETGID`, `CAP_SETUID`,
`CAP_MKNOD`, `CAP_SETFCAP`
(and `CAP_DAC_READ_SEARCH` if `--inode-file-handles` is used).

```shell
virtiofsd [FLAGS] [OPTIONS] --fd <fd>|--socket-path <socket-path> --shared-dir <shared-dir>
```
#### Flags
```shell
-h, --help
```
Prints help information.

```shell
-V, --version
```
Prints version information.

```shell
--syslog
```
Log to syslog. Default: stderr.

```shell
--print-capabilities
```
Print vhost-user.json backend program capabilities and exit.

```shell
--allow-direct-io
```
Honor the `O_DIRECT` flag passed down by guest applications.

```shell
--announce-submounts
```
Tell the guest which directories are mount points.
If multiple filesystems are mounted in the shared directory,
virtiofsd passes inode IDs directly to the guest, and because such IDs
are unique only on a single filesystem, it is possible that the guest
will encounter duplicates if multiple filesystems are mounted in the
shared directory.
`--announce-submounts` solves that problem because it reports a different
device number for every submount it encounters.

In addition, when running with `--announce-submounts`, the client sends one
`SYNCFS` request per submount that is to be synced, so virtiofsd
will call `syncfs()` on each submount.
On the other hand, when running without `--announce-submounts`,
the client only sends a `SYNCFS` request for the root mount,
this may lead to data loss/corruption.

```shell
--no-killpriv-v2
```
Disable `KILLPRIV V2` support.
This is required if the shared directory is an NFS file system.

```shell
--no-readdirplus
```
Disable support for `READDIRPLUS` operations.

```shell
--writeback
```
Enable writeback cache.

```shell
--xattr
```
Enable support for extended attributes.

#### Options
```shell
--shared-dir <shared-dir>
```
Shared directory path.

```shell
--socket-group <socket-group>
```
Name of group for the vhost-user socket.

```shell
--socket-path <socket-path>
```
vhost-user socket path.

```shell
--fd <fd>
```
File descriptor for the listening socket.

```shell
--log-level <log-level>
```
Log level (error, warn, info, debug, trace, off).

Default: info.

```shell
--thread-pool-size <thread-pool-size>
```
Maximum thread pool size. A value of "0" disables the pool.

Default: 0.

```shell
--rlimit-nofile <rlimit-nofile>
```
Set maximum number of file descriptors (0 leaves rlimit unchanged).

Default: the value read from `/proc/sys/fs/nr_open`.

```shell
--modcaps=<modcaps>
```
Modify the list of capabilities, e.g., `--modcaps=+sys_admin:-chown`.
Although it is not mandatory, it is recommended to always use the `=` sign,
in other case, this will fail  `--modcaps -mknod`, because it will be
interpreted as two options, instead of the intended `--modcaps=-mknod`.

```shell
--sandbox <sandbox>
```
Sandbox mechanism to isolate the daemon process (namespace, chroot, none).

- **namespace**: The program switches into a new file system
namespace (`namespaces(7)`) and invokes `pivot_root(2)` to make the shared directory
tree its root. A new mount (`mount_namespaces(7)`), pid (`pid_namespaces(7)`) and
net namespace (`network_namespaces(7)`) is also created to isolate the process.

- **chroot**: The program invokes `chroot(2)` to make the shared
directory tree its root. This mode is intended for container environments where
the container runtime has already set up the namespaces and the program does
not have permission to create namespaces itself.

- **none**: Do not isolate the daemon (not recommended).

Both **namespace** and **chroot** sandbox modes prevent "file system escapes"
due to symlinks and other file system objects that might lead to files outside
the shared directory.

Default: namespace.

```shell
--seccomp <seccomp>
```
Action to take when seccomp finds a not allowed syscall (none, kill, log, trap).

Default: kill.

```shell
--cache <cache>
```
The caching policy the file system should use (auto, always, never).

Default: auto.

```shell
--inode-file-handles=<inode-file-handles>
```
When to use file handles to reference inodes instead of `O_PATH` file descriptors (never, prefer, mandatory).

- **never**: Never use file handles, always use `O_PATH` file descriptors.

- **prefer**: Attempt to generate file handles, but fall back to `O_PATH` file descriptors where the underlying
  filesystem does not support file handles or `CAP_DAC_READ_SEARCH` is not available.
  Useful when there are various different filesystems under the shared directory and some of them do not support file handles.

- **mandatory**: Always use file handles.
  It will fail if the underlying filesystem does not support file handles or `CAP_DAC_READ_SEARCH` is not available.

Using file handles reduces the number of file descriptors virtiofsd keeps open, which is not only helpful
with resources, but may also be important in cases where virtiofsd should only have file descriptors open
for files that are open in the guest, e.g. to get around bad interactions with NFS's silly renaming
(see [NFS FAQ, Section D2: "What is a "silly rename"?"](http://nfs.sourceforge.net/)).

Default: never.

```shell
--xattrmap <xattrmap>
```
Add custom rules for translating extended attributes between host and guest (e.g., `:map::user.virtiofs.:`).
For additional details please see [Extended attribute mapping](doc/xattr-mapping.md).

### Examples
Export `/mnt` on vhost-user UNIX domain socket `/tmp/vfsd.sock`:

```shell
host# virtiofsd --socket-path=/tmp/vfsd.sock --shared-dir /mnt \
        --announce-submounts --inode-file-handles=mandatory &

host# qemu-system \
        -blockdev file,node-name=hdd,filename=<your image> \
        -device virtio-blk,drive=hdd \
        -chardev socket,id=char0,path=/tmp/vfsd.sock \
        -device vhost-user-fs-pci,queue-size=1024,chardev=char0,tag=myfs \
        -object memory-backend-file,id=mem,size=4G,mem-path=/dev/shm,share=on \
        -numa node,memdev=mem \
        -accel kvm -m 4G

guest# mount -t virtiofs myfs /mnt
```

### Running as non-privileged user
When run without root, virtiofsd requires a user namespace (see `user_namespaces(7)`)
to be able to switch between arbitrary user/group IDs within the guest.
virtiofsd will fail in a user namespace where UIDs/GIDs have not been mapped
(i.e., `uid_map` and `gid_map` files have not been written).
There are many options to run virtiofsd inside a user namespace.
For instance:

Let's assume the invoking UID and GID is 1000 and the content of both `/etc/subuid`
and `/etc/subgid` are:
```
1000:100000:65536
```

Using `podman-unshare(1)` the user namespace will be configured so that the invoking user's UID
and primary GID (i.e., 1000) appear to be UID 0 and GID 0, respectively.
Any ranges which match that user and group in `/etc/subuid` and `/etc/subgid` are also
mapped in as themselves with the help of the `newuidmap(1)` and `newgidmap(1)` helpers:

```shell
host$ podman unshare -- virtiofsd --socket-path=/tmp/vfsd.sock --shared-dir /mnt \
        --announce-submounts --sandbox chroot &
```

Using `lxc-usernsexec(1)`, we could leave the invoking user outside the mapping, having
the root user inside the user namespace mapped to the user and group 100000:

```shell
host$ lxc-usernsexec -m b:0:100000:65536 -- virtiofsd --socket-path=/tmp/vfsd.sock \
        --shared-dir /mnt --announce-submounts --sandbox chroot &
```

In order to have the same behavior as `podman-unshare(1)`, we need to run

```shell
host$ lxc-usernsexec -m b:0:1000:1 -m b:1:100000:65536 -- virtiofsd --socket-path=/tmp/vfsd.sock \
        --shared-dir /mnt --announce-submounts --sandbox chroot &
```

We could also select `--sandbox none` instead of `--sandbox chroot`.

#### Limitations
- Within the guest, it is not possible to create block or char device nodes in the shared directory.

- virtiofsd can't use file handles (`--inode-file-handles` requires `CAP_DAC_READ_SEARCH`),
  so a large number of file descriptors is required.
  Additionally, on NFS, not using file handles may result in a hidden file lingering after some file is deleted
  (see [NFS FAQ, Section D2: "What is a "silly rename"?"](http://nfs.sourceforge.net/)).

- virtiofsd will not be able to increase `RLIMIT_NOFILE`.

## FAQ
- How to read-only-share a directory that cannot be modified within the guest?
To accomplish this you need to export a read-only mount point, for instance,
exporting `share`:

```shell
mkdir ro-share
mount -o bind,ro share ro-share
virtiofsd --shared-dir ro-share ...
```

- How to share multiple directories with the same virtiofsd?
Currently, virtiofsd only supports sharing a single directory,
but it is possible to use submounts to achieve this, for instance,
exporting `share0`, `share1`:

```shell
mkdir -p share/{sh0,sh1}
mount -o bind share0 share/sh0
mount -o bind share1 share/sh1
virtiofsd --announce-submounts --shared-dir share ...
```
Note the use of `--announce-submounts` to prevent data loss/corruption.
