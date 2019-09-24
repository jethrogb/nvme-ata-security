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

# Running nvme-ata-security

This project is written in Rust. Make sure `cargo` is installed. On ubuntu::
  sudo apt install cargo
  cd user
  cargo build
  
Run the project with::
  cd target/debug
  ./nvme-ata-security
