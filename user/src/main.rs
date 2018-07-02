/*
 * Linux userspace tool to configure ATA security on NVMe drives
 *
 * (C) Copyright 2016 Jethro G. Beekman
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

#[macro_use]
extern crate nix;
#[macro_use]
extern crate bitflags;
extern crate byteorder;
extern crate docopt;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate libc;
extern crate rpassword;
extern crate sha2;

mod nvme;
mod ops;

use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::io::AsRawFd;
use std::result::Result as StdResult;

use sha2::{Digest, Sha256};

use nvme::identify::IdentifyController;
use nvme::security::Protocol::AtaSecurity as ProtocolAtaSecurity;
use nvme::security::{AtaSecurityIdentify, AtaSecurityPassword, AtaSecuritySpecific};
use ops::Result;

fn security_protocols(
	f: &File,
	identity: &IdentifyController,
) -> Result<Option<Vec<nvme::security::Protocol>>> {
	use byteorder::{BigEndian, ReadBytesExt};

	let fd = f.as_raw_fd();
	if identity.oacs().contains(nvme::identify::Oacs::SECURITY) {
		let mut supported = vec![0u8; 8];
		try!(ops::security_receive(fd, 0, 0, 0, &mut supported));
		let bytes = (&supported[6..8]).read_u16::<BigEndian>().unwrap();
		if bytes > 0 {
			supported.resize(bytes as usize + 8, 0);
			try!(ops::security_receive(fd, 0, 0, 0, &mut supported));
			Ok(Some(
				supported
					.into_iter()
					.skip(8)
					.map(Into::<nvme::security::Protocol>::into)
					.collect(),
			))
		} else {
			Ok(Some(Vec::with_capacity(0)))
		}
	} else {
		Ok(None)
	}
}

fn ata_identify(
	f: &File,
	protocols: &[nvme::security::Protocol],
) -> Result<Option<AtaSecurityIdentify>> {
	if !protocols.contains(&ProtocolAtaSecurity) {
		return Ok(None);
	}

	let mut buf = [0u8; 16];
	try!(ops::security_receive(
		f.as_raw_fd(),
		ProtocolAtaSecurity.into(),
		0,
		0,
		&mut buf
	));
	Ok(Some(AtaSecurityIdentify::from(buf)))
}

struct DriveInfo(
	Result<(
		IdentifyController,
		Result<
			(Option<(
				Vec<nvme::security::Protocol>,
				Result<Option<AtaSecurityIdentify>>,
			)>),
		>,
	)>,
);

impl fmt::Display for DriveInfo {
	fn fmt(&self, fmt: &mut fmt::Formatter) -> StdResult<(), fmt::Error> {
		let r_i = &self.0;
		let (i, r_p) = match r_i {
			&Err(ref e) => {
				try!(writeln!(
					fmt,
					"There was an error obtaining NVMe identity information:\n{:?}",
					e
				));
				return Ok(());
			}
			&Ok((ref i, ref r_p)) => (i, r_p),
		};
		try!(writeln!(
			fmt,
			"vid:ssvid: {:04x}:{:04x}
model: {}
serial: {}
firmware: {}
oacs: {:?}",
			i.vid(),
			i.ssvid(),
			String::from_utf8_lossy(i.sn()),
			String::from_utf8_lossy(i.mn()),
			String::from_utf8_lossy(i.fr()),
			i.oacs()
		));
		let (protocols, r_s) = match r_p {
			&Err(ref e) => {
				try!(writeln!(
					fmt,
					"There was an error enumerating supported NVMe security protocols:\n{:?}",
					e
				));
				return Ok(());
			}
			&Ok(None) => {
				try!(writeln!(
					fmt,
					"This drive does not support NVMe security commands."
				));
				return Ok(());
			}
			&Ok(Some((ref p, ref r_s))) => (p, r_s),
		};
		try!(writeln!(fmt, "protocols: {:?}", protocols));
		let security = match r_s {
			&Err(ref e) => {
				try!(writeln!(
					fmt,
					"There was an error obtaining ATA security information:\n{:?}",
					e
				));
				return Ok(());
			}
			&Ok(None) => {
				try!(writeln!(
					fmt,
					"This drive does not support ATA security commands."
				));
				return Ok(());
			}
			&Ok(Some(ref s)) => s,
		};
		try!(writeln!(
			fmt,
			"ata security: erase time: {} enhanced erase time: {}, master pwd id: {:04x} maxset: {}
s_suprt: {} s_enabld: {} locked: {} frozen: {} pwncntex: {} en_er_sup: {}",
			security.security_erase_time(),
			security.enhanced_security_erase_time(),
			security.master_password_identifier(),
			security.maxset(),
			security.s_suprt(),
			security.s_enabld(),
			security.locked(),
			security.frozen(),
			security.pwncntex(),
			security.en_er_sup()
		));
		if !security.s_suprt() {
			try!(writeln!(fmt, "This drive does not support ATA security."));
		}
		Ok(())
	}
}

impl DriveInfo {
	fn query(f: &File) -> DriveInfo {
		DriveInfo(ops::identify_controller(f.as_raw_fd()).map(|i| {
			let p = security_protocols(&f, &i).map(|opt_p| {
				opt_p.map(|p| {
					let s = ata_identify(&f, &p);
					(p, s)
				})
			});
			(i, p)
		}))
	}

	fn check_support(self) -> Option<(IdentifyController, AtaSecurityIdentify)> {
		match self.0 {
			Err(e) => {
				eprintln!(
					"There was an error obtaining NVMe identity information:\n{:?}",
					e
				);
				None
			}
			Ok((_, Err(e))) => {
				eprintln!(
					"There was an error enumerating supported NVMe security protocols:\n{:?}",
					e
				);
				None
			}
			Ok((_, Ok(None))) => {
				eprintln!("This drive does not support NVMe security commands.");
				None
			}
			Ok((_, Ok(Some((_, Err(e)))))) => {
				eprintln!(
					"There was an error obtaining ATA security information:\n{:?}",
					e
				);
				None
			}
			Ok((_, Ok(Some((_, Ok(None)))))) => {
				eprintln!("This drive does not support ATA security commands.");
				None
			}
			Ok((i, Ok(Some((_, Ok(Some(s))))))) => Some((i, s)),
		}
	}
}

fn security_set_password_user(f: &File, password: [u8; 32], maximum_security: bool) -> Result<()> {
	let buf: [u8; 36] =
		AtaSecurityPassword::new(password, false, Some(maximum_security), None).into();
	ops::security_send(
		f.as_raw_fd(),
		ProtocolAtaSecurity.into(),
		AtaSecuritySpecific::SetPassword as u16,
		0,
		Some(&buf),
	)
}

fn security_set_password_master(f: &File, password: [u8; 32], id: u16) -> Result<()> {
	let buf: [u8; 36] = AtaSecurityPassword::new(password, true, None, Some(id)).into();
	ops::security_send(
		f.as_raw_fd(),
		ProtocolAtaSecurity.into(),
		AtaSecuritySpecific::SetPassword as u16,
		0,
		Some(&buf),
	)
}

fn security_unlock(f: &File, password: [u8; 32], master: bool) -> Result<()> {
	let buf: [u8; 36] = AtaSecurityPassword::new(password, master, None, None).into();
	try!(ops::security_send(
		f.as_raw_fd(),
		ProtocolAtaSecurity.into(),
		AtaSecuritySpecific::Unlock as u16,
		0,
		Some(&buf)
	));
	ops::ioctl_blkrrpart(f.as_raw_fd())
}

fn security_erase(f: &File, password: [u8; 32], master: bool, enhanced: bool) -> Result<()> {
	try!(ops::security_send(
		f.as_raw_fd(),
		ProtocolAtaSecurity.into(),
		AtaSecuritySpecific::ErasePrepare as u16,
		0,
		None
	));
	let buf: [u8; 36] = AtaSecurityPassword::new(password, master, Some(enhanced), None).into();
	ops::security_send(
		f.as_raw_fd(),
		ProtocolAtaSecurity.into(),
		AtaSecuritySpecific::EraseUnit as u16,
		0,
		Some(&buf),
	)
}

fn security_freeze(f: &File) -> Result<()> {
	ops::security_send(
		f.as_raw_fd(),
		ProtocolAtaSecurity.into(),
		AtaSecuritySpecific::FreezeLock as u16,
		0,
		None,
	)
}

fn security_disable_password(f: &File, password: [u8; 32], master: bool) -> Result<()> {
	let buf: [u8; 36] = AtaSecurityPassword::new(password, master, None, None).into();
	ops::security_send(
		f.as_raw_fd(),
		ProtocolAtaSecurity.into(),
		AtaSecuritySpecific::DisablePassword as u16,
		0,
		Some(&buf),
	)
}

fn read_password_err(
	src: Option<String>,
	identity: &IdentifyController,
	confirm: bool,
) -> std::result::Result<[u8; 32], io::Error> {
	let mut f_file;
	let mut f_stdin;
	let f_password;
	let mut f_password_ptr;
	let f: &mut Read = if let Some(src) = src {
		f_file = try!(File::open(src));
		&mut f_file
	} else {
		if nix::unistd::isatty(0).unwrap_or(false) {
			loop {
				eprint!(
					"Please enter password for {} {}:",
					String::from_utf8_lossy(identity.mn()).trim(),
					String::from_utf8_lossy(identity.sn()).trim()
				);
				let password1 = try!(rpassword::read_password());
				if password1.len() == 0 {
					continue;
				} else if password1.len() > 32 {
					eprintln!("Password too long!");
					continue;
				}
				if confirm {
					eprint!("Enter password again:");
					let password2 = try!(rpassword::read_password());
					if password1 != password2 {
						eprintln!("Passwords don't match!");
						continue;
					}
				}
				f_password = password1;
				break;
			}
			f_password_ptr = f_password.as_bytes();
			&mut f_password_ptr
		} else {
			f_stdin = io::stdin();
			&mut f_stdin
		}
	};

	let mut buf = vec![];
	try!(f.read_to_end(&mut buf));
	let mut out = [0u8; 32];
	let mut sha256 = Sha256::new();
	sha256.input(&buf);
	sha256.input(&identity.mn());
	sha256.input(&identity.sn());
	out.copy_from_slice(&sha256.result());
	Ok(out)
}

fn read_password(src: Option<String>, identity: &IdentifyController, confirm: bool) -> [u8; 32] {
	match read_password_err(src, identity, confirm) {
		Err(e) => {
			eprintln!("Error trying to read password: {}", e);
			std::process::exit(1);
		}
		Ok(v) => v,
	}
}

trait RetryIterator: Iterator {
	fn retry_results<T, E>(&mut self) -> std::result::Result<T, E>
	where
		Self: Iterator<Item = std::result::Result<T, E>>,
	{
		let mut last = None;
		loop {
			let cur = self.next();
			match cur {
				Some(v @ Ok(_)) => {
					return v;
				}
				Some(e @ Err(_)) => {
					last = Some(e);
				}
				None => if let Some(e) = last {
					return e;
				},
			}
		}
	}

	fn retry_options<T>(&mut self) -> Option<T>
	where
		Self: Iterator<Item = Option<T>>,
	{
		let mut last = None;
		loop {
			let cur = self.next();
			match cur {
				Some(v @ Some(_)) => {
					return v;
				}
				Some(e @ None) => {
					last = Some(e);
				}
				None => if let Some(e) = last {
					return e;
				},
			}
		}
	}
}

impl<T: Iterator> RetryIterator for T {}

fn main() {
	#[derive(Deserialize, Debug)]
	#[allow(dead_code)]
	struct Args {
		cmd_query: bool,
		cmd_set_password: bool,
		cmd_unlock: bool,
		cmd_disable_password: bool,
		cmd_erase: bool,
		cmd_freeze: bool,
		arg_dev: String,
		flag_password_file: Option<String>,
		flag_tries: Option<u8>,
		flag_id: u16,
		flag_user: bool,
		flag_master: bool,
		flag_high: bool,
		flag_max: bool,
		flag_enhanced: bool,
	}

	const USAGE: &'static str = "
Usage:
	nvme-ata-security query <dev>
	nvme-ata-security set-password -u (--high|--max) [--password-file=<file>] <dev>
	nvme-ata-security set-password -m --id=<id> [--password-file=<file>] <dev>
	nvme-ata-security unlock (-u|-m) [--password-file=<file>|--tries=<num>] <dev>
	nvme-ata-security disable-password (-u|-m) [--password-file=<file>] <dev>
	nvme-ata-security erase (-u|-m) [--enhanced] [--password-file=<file>] <dev>
	nvme-ata-security freeze <dev>
	nvme-ata-security --help
	
Options:
	-u, --user                         Specify the user password
	-m, --master                       Specify the master password
	-i <file>, --password-file=<file>  Read the password from <file> instead of stdin
	-t <num>, --tries=<num>            When reading from stdin, try unlocking <num> times
	--high                             Configure high security
	--max                              Configure maximum security
	--id=<id>                          Set the master password identifier
	--enhanced                         Perform an enhanced security erase
";

	let args: Args = docopt::Docopt::new(USAGE)
		.and_then(|d| d.argv(std::env::args()).deserialize())
		.unwrap_or_else(|e| e.exit());
	let f = match File::open(&args.arg_dev) {
		Err(e) => {
			eprintln!("Unable to open {} for reading: {}", args.arg_dev, e);
			return;
		}
		Ok(f) => f,
	};
	match f.metadata() {
		Err(e) => {
			eprintln!("Unable to stat {}: {}", args.arg_dev, e);
			return;
		}
		Ok(ref m) if !m.file_type().is_block_device() => {
			eprintln!("{} is not a block device", args.arg_dev);
			return;
		}
		Ok(_) => {}
	};

	let info = DriveInfo::query(&f);
	let identity = if args.cmd_query {
		eprint!("{}", info);
		return;
	} else {
		match info.check_support() {
			Some((identity, _)) => identity,
			None => {
				return;
			}
		}
	};

	let result = if args.cmd_set_password {
		eprintln!("Performing SECURITY SET PASSWORD...");
		if args.flag_user {
			security_set_password_user(
				&f,
				read_password(args.flag_password_file, &identity, true),
				args.flag_max,
			)
		} else {
			security_set_password_master(
				&f,
				read_password(args.flag_password_file, &identity, true),
				args.flag_id,
			)
		}
	} else if args.cmd_unlock {
		if let Some(_) = args.flag_password_file {
			eprintln!("Performing SECURITY UNLOCK...");
			security_unlock(
				&f,
				read_password(args.flag_password_file, &identity, false),
				args.flag_master,
			)
		} else {
			if args.flag_tries == Some(0) {
				return;
			}
			std::iter::repeat(())
				.take(args.flag_tries.unwrap_or(1) as usize)
				.map(|_| {
					eprintln!("Performing SECURITY UNLOCK...");
					security_unlock(&f, read_password(None, &identity, false), args.flag_master)
				})
				.retry_results()
		}
	} else if args.cmd_disable_password {
		eprintln!("Performing SECURITY DISABLE PASSWORD...");
		security_disable_password(
			&f,
			read_password(args.flag_password_file, &identity, false),
			args.flag_master,
		)
	} else if args.cmd_erase {
		eprintln!("Performing SECURITY ERASE...");
		security_erase(
			&f,
			read_password(args.flag_password_file, &identity, true),
			args.flag_master,
			args.flag_enhanced,
		)
	} else if args.cmd_freeze {
		eprintln!("Performing SECURITY FREEZE...");
		security_freeze(&f)
	} else {
		unreachable!()
	};

	if let Err(e) = result {
		eprintln!("There was an error executing the command: {:?}", e);
	} else {
		eprintln!("Success!");
	}
}
