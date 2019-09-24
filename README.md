# nvme-ata-security

ATA defines the ATA Security feature set, more commonly known as the ability to 
set a “hard drive password.” Most modern SSDs use this password to derive an 
encryption key.

NVMe is a relatively new interface to attach SSDs directly to the PCIe bus 
instead of using SATA. This of course means that most ATA features are not 
directly supported, but some drives do support the ATA Security feature set 
through a compatibility layer.

This repository contains Linux tools to deal with such drives.

You will want to use [this kernel patch](http://lists.infradead.org/pipermail/linux-nvme/2016-June/005114.html).

## mkinitcpio/

mkinitcpio hook to ask for drive passwords during boot.

## user/

Userspace tool to configure and use passwords on such drives.

# Building & running

nvme-ata-security is written in [Rust](https://www.rust-lang.org/). You can install it using your system's package manager (package name: `cargo`, probably) or directly, see https://www.rust-lang.org/tools/install. With Rust installed:

```
cd user
cargo build
```

To run:

```
cargo run
```

or

```
target/debug/nvme-ata-security
```
