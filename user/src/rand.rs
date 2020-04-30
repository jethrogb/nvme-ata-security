/*
 * Linux userspace tool to configure ATA security on NVMe drives
 *
 * (C) Copyright 2018 Jethro G. Beekman
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */
//! Emulate the `getrandom` syscall.
//!
//! Calls to the Linux `getrandom` syscall can block during early boot because
//! there is not a lot of entropy available. We don't really need entropy for
//! anything, but dependencies use `HashMap` which requires entropy to
//! initialize. This module installs a seccomp filter that catches `getrandom`
//! syscalls and emulates the call using the `RDRAND` instruction.

use std::mem;
use std::slice;

use byteorder::{ByteOrder, NativeEndian};
use libc::{SIGSYS, *};
use nix::sys::signal::{sigaction, *};

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("This module will only work on Linux x86-64");

extern "C" fn handle_sigsys(_signo: c_int, info: *mut siginfo_t, context: *mut c_void) {
	fn rdrand64() -> u64 {
		unsafe {
			let mut ret: u64 = mem::MaybeUninit::<u64>::uninit().assume_init();
			for _ in 0..10 {
				if ::std::arch::x86_64::_rdrand64_step(&mut ret) == 1 {
					return ret;
				}
			}
			panic!("Failed to obtain random data");
		}
	}

	unsafe {
		let context = &mut *(context as *mut ucontext_t);
		let info = &mut *info;

		// Check that this signal was sent by seccomp, see `man seccomp(2)`
		assert_eq!(info.si_signo, SIGSYS);
		assert_eq!(info.si_code, SYS_SECCOMP);
		assert_eq!(info.si_errno, 0);
		/* missing fields in `libc` crate
		assert_eq!(info.si_call_addr, ...);
		assert_eq!(info.si_syscall, ...);
		assert_eq!(info.si_arch, ...);
		*/

		// Check that this is the getrandom syscall
		assert_eq!(context.uc_mcontext.gregs[Greg::RAX as usize], SYS_getrandom);

		// Emulate the getrandom syscall
		let buf = context.uc_mcontext.gregs[Greg::RDI as usize] as *mut u8;
		let buflen = context.uc_mcontext.gregs[Greg::RSI as usize] as usize;
		let ret = &mut context.uc_mcontext.gregs[Greg::RAX as usize];

		if buf.is_null() {
			if buflen == 0 {
				*ret = 0;
			} else {
				*ret = -EFAULT as _;
			}
		} else {
			let buf = slice::from_raw_parts_mut(buf, buflen);

			for chunk in buf.chunks_mut(mem::size_of::<u64>()) {
				let len = chunk.len();
				NativeEndian::write_uint(chunk, rdrand64() & ((!0u64) >> (64 - (len * 8))), len);
			}

			*ret = buflen as _;
		}
	}
}

pub fn init() {
	static FILTER: &'static [sock_filter] = &[
		/* [0] Load architecture from 'seccomp_data' buffer into accumulator */
		sock_filter {
			code: BPF_LD | BPF_W | BPF_ABS,
			k: OFFSET_OF_SECCOMP_DATA_ARCH,
			jt: 0,
			jf: 0,
		},
		/* [1] Jump forward 5 instructions if architecture does not match 'x86-64' */
		sock_filter {
			code: BPF_JMP | BPF_JEQ | BPF_K,
			k: SCMP_ARCH_X86_64,
			jt: 0,
			jf: 5,
		},
		/* [2] Load system call number from 'seccomp_data' buffer into accumulator */
		sock_filter {
			code: BPF_LD | BPF_W | BPF_ABS,
			k: OFFSET_OF_SECCOMP_DATA_NR,
			jt: 0,
			jf: 0,
		},
		/* [3] Check ABI - only needed for x86-64 in blacklist use
			  cases.  Use BPF_JGT instead of checking against the bit
			  mask to avoid having to reload the syscall number. */
		sock_filter {
			code: BPF_JMP | BPF_JGT | BPF_K,
			k: UPPER_SYSCALL_NR,
			jt: 3,
			jf: 0,
		},
		/* [4] Jump forward 1 instruction if system call number does not match 'getrandom' */
		sock_filter {
			code: BPF_JMP | BPF_JEQ | BPF_K,
			k: SYS_getrandom as _,
			jt: 0,
			jf: 1,
		},
		/* [5] Matching architecture and system call: trap and emulate */
		sock_filter {
			code: BPF_RET | BPF_K,
			k: SECCOMP_RET_TRAP,
			jt: 0,
			jf: 0,
		},
		/* [6] Destination of system call number mismatch: allow other system calls */
		sock_filter {
			code: BPF_RET | BPF_K,
			k: SECCOMP_RET_ALLOW,
			jt: 0,
			jf: 0,
		},
		/* [7] Destination of architecture mismatch: kill task */
		sock_filter {
			code: BPF_RET | BPF_K,
			k: SECCOMP_RET_KILL_PROCESS,
			jt: 0,
			jf: 0,
		},
	];

	unsafe {
		if prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
			panic!("PR_SET_NO_NEW_PRIVS failed: {}", ::nix::Error::last());
		}

		let prog = sock_fprog {
			filter: FILTER.as_ptr(),
			len: FILTER.len() as _,
		};

		if prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) != 0 {
			panic!("PR_SET_SECCOMP failed: {}", ::nix::Error::last());
		}

		sigaction(
			Signal::SIGSYS,
			&SigAction::new(
				SigHandler::SigAction(handle_sigsys),
				SaFlags::empty(),
				SigSet::empty(),
			),
		).unwrap();
	}
}

// ======== BPF definitions ========

#[repr(C)]
struct sock_fprog {
	len: c_ushort,              /* Number of BPF instructions */
	filter: *const sock_filter, /* Pointer to array of BPF instructions */
}

#[repr(C)]
struct sock_filter {
	/* Filter block */
	code: u16, /* Actual filter code */
	jt: u8,    /* Jump true */
	jf: u8,    /* Jump false */
	k: u32,    /* Generic multiuse field */
}

const BPF_LD: u16 = 0x00;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JEQ: u16 = 0x10;
const BPF_JGT: u16 = 0x20;
const BPF_K: u16 = 0x00;

// ======== seccomp definitions ========

const SCMP_ARCH_X86_64: u32 = 0xc000003e;

const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000; /* kill the process */
const SECCOMP_RET_TRAP: u32 = 0x00030000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;

#[allow(unused)]
#[repr(C)]
struct seccomp_data {
	nr: c_int,                /* System call number */
	arch: u32,                /* AUDIT_ARCH_* value (see <linux/audit.h>) */
	instruction_pointer: u64, /* CPU instruction pointer */
	args: [u64; 6],           /* Up to 6 system call arguments */
}

const OFFSET_OF_SECCOMP_DATA_NR: u32 = 0;
const OFFSET_OF_SECCOMP_DATA_ARCH: u32 = 4;

#[allow(unused)]
fn _seccomp_data_arch_offset_check() {
	#[repr(C)]
	struct seccomp_data_arch_offset_check1 {
		nr: c_int,
		arch: u32,
	}

	#[repr(C, packed)]
	struct seccomp_data_arch_offset_check2 {
		nr: [u8; OFFSET_OF_SECCOMP_DATA_ARCH as _],
		arch: u32,
	}
	unsafe {
		mem::transmute::<seccomp_data_arch_offset_check1, seccomp_data_arch_offset_check2>(
			unimplemented!(),
		)
	};
}

// ======== siginfo definitions ========

const SYS_SECCOMP: i32 = 1;

// ======== architectural definitions ========

const X32_SYSCALL_BIT: u32 = 0x40000000;
const UPPER_SYSCALL_NR: u32 = X32_SYSCALL_BIT - 1;

#[repr(C)]
#[allow(unused)]
enum Greg {
	R8 = 0,
	R9,
	R10,
	R11,
	R12,
	R13,
	R14,
	R15,
	RDI,
	RSI,
	RBP,
	RBX,
	RDX,
	RAX,
	RCX,
	RSP,
	RIP,
	EFL,
	CSGSFS, /* Actually short cs, gs, fs, __pad0. */
	ERR,
	TRAPNO,
	OLDMASK,
	CR2,
}
