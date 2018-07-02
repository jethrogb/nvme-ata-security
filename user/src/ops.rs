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

use nix::Error as NixError;
use nvme;
use std::os::unix::io::RawFd;

#[derive(Debug)]
pub enum Error {
	Io(NixError),
	Nvme(nvme::StatusCode),
}

impl From<NixError> for Error {
	fn from(err: NixError) -> Error {
		Error::Io(err)
	}
}

impl From<nvme::StatusCode> for Error {
	fn from(err: nvme::StatusCode) -> Error {
		Error::Nvme(err)
	}
}

pub type Result<T> = ::std::result::Result<T, Error>;

pub fn identify_controller(fd: RawFd) -> Result<nvme::identify::IdentifyController> {
	let mut buf = [0u8; 4096];
	unsafe {
		try!(nvme_ioctl_admin_cmd(
			fd,
			NvmeAdminCmd {
				opcode: nvme::Opcode::AdminIdentify as u8,
				addr: &mut buf as *mut _ as usize as u64,
				data_len: 4096,
				nsid: 0,
				cdw10: 1,
				..Default::default()
			}
		))
	}
	return Ok(nvme::identify::IdentifyController::from(buf));
}

pub fn security_send(fd: RawFd, secp: u8, spsp: u16, nssf: u8, data: Option<&[u8]>) -> Result<()> {
	assert!(data.map(|d| d.len()).unwrap_or(0) <= ::std::u32::MAX as usize);
	unsafe {
		nvme_ioctl_admin_cmd(
			fd,
			NvmeAdminCmd {
				opcode: nvme::Opcode::AdminSecuritySend as u8,
				nsid: try!(nvme_ioctl_id(fd)),
				addr: data.map(|d| d.as_ptr() as usize as u64).unwrap_or(0),
				data_len: data.map(|d| d.len() as u32).unwrap_or(0),
				cdw11: data.map(|d| d.len() as u32).unwrap_or(0),
				cdw10: (secp as u32) << 24 | (spsp as u32) << 8 | (nssf as u32),
				..Default::default()
			},
		)
	}
}

pub fn security_receive(fd: RawFd, secp: u8, spsp: u16, nssf: u8, data: &mut [u8]) -> Result<()> {
	assert!(data.len() <= ::std::u32::MAX as usize);
	unsafe {
		nvme_ioctl_admin_cmd(
			fd,
			NvmeAdminCmd {
				opcode: nvme::Opcode::AdminSecurityReceive as u8,
				nsid: try!(nvme_ioctl_id(fd)),
				addr: data.as_mut_ptr() as usize as u64,
				data_len: data.len() as u32,
				cdw11: data.len() as u32,
				cdw10: (secp as u32) << 24 | (spsp as u32) << 8 | (nssf as u32),
				..Default::default()
			},
		)
	}
}

unsafe fn nvme_ioctl_admin_cmd(fd: RawFd, mut cmd: NvmeAdminCmd) -> Result<()> {
	let ret = raw_nvme_ioctl_admin_cmd(fd, &mut cmd)?;
	if ret != 0 {
		Err(Error::Nvme(nvme::StatusCode::from(ret as u16)))
	} else {
		Ok(())
	}
}

pub fn ioctl_blkrrpart(fd: RawFd) -> Result<()> {
	let ret = unsafe { raw_ioctl_blkrrpart(fd) }?;
	if ret != 0 {
		panic!("Unexpected return value from BLKRRPART ioctl: {}", ret);
	} else {
		Ok(())
	}
}

pub fn nvme_ioctl_id(fd: RawFd) -> Result<u32> {
	let ret = unsafe { raw_nvme_ioctl_id(fd) }?;
	Ok(ret as u32)
}

use self::ioctl::*;
mod ioctl {
	#[derive(Default)]
	#[repr(packed, C)]
	pub struct NvmeAdminCmd {
		pub opcode: u8,
		pub flags: u8,
		pub rsvd1: u16,
		pub nsid: u32,
		pub cdw2: u32,
		pub cdw3: u32,
		pub metadata: u64,
		pub addr: u64,
		pub metadata_len: u32,
		pub data_len: u32,
		pub cdw10: u32,
		pub cdw11: u32,
		pub cdw12: u32,
		pub cdw13: u32,
		pub cdw14: u32,
		pub cdw15: u32,
		pub timeout_ms: u32,
		pub result: u32,
	}

	ioctl_none!(raw_nvme_ioctl_id, b'N', 0x40);
	ioctl_readwrite!(raw_nvme_ioctl_admin_cmd, b'N', 0x41, NvmeAdminCmd);

	ioctl_none!(raw_ioctl_blkrrpart, 0x12, 95);
}
