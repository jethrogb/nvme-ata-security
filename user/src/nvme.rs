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

#[repr(u8)]
pub enum Opcode {
	AdminIdentify = 0x06,
	AdminSecuritySend = 0x81,
	AdminSecurityReceive = 0x82,
}

#[derive(Debug, PartialEq, Eq)]
pub enum StatusCode {
	SuccessfulCompletion,                           // 0x000
	InvalidCommandOpcode,                           // 0x001
	InvalidFieldInCommand,                          // 0x002
	CommandIdConflict,                              // 0x003
	DataTransferError,                              // 0x004
	CommandsAbortedDueToPowerLossNotification,      // 0x005
	InternalError,                                  // 0x006
	CommandAbortRequested,                          // 0x007
	CommandAbortedDueToSqDeletion,                  // 0x008
	CommandAbortedDueToFailedFusedCommand,          // 0x009
	CommandAbortedDueToMissingFusedCommand,         // 0x00a
	InvalidNamespaceOrFormat,                       // 0x00b
	CommandSequenceError,                           // 0x00c
	InvalidSglSegmentDescriptor,                    // 0x00d
	InvalidNumberOfSglDescriptors,                  // 0x00e
	DataSglLengthInvalid,                           // 0x00f
	MetadataSglLengthInvalid,                       // 0x010
	SglDescriptorTypeInvalid,                       // 0x011
	InvalidUseOfControllerMemoryBuffer,             // 0x012
	PrpOffsetInvalid,                               // 0x013
	AtomicWriteUnitExceeded,                        // 0x014
	SglOffsetInvalid,                               // 0x016
	SglSubTypeInvalid,                              // 0x017
	HostIdentifierInconsistentFormat,               // 0x018
	KeepAliveTimeoutExpired,                        // 0x019
	KeepAliveTimeoutInvalid,                        // 0x01a
	LbaOutOfRange,                                  // 0x080
	CapacityExceeded,                               // 0x081
	NamespaceNotReady,                              // 0x082
	ReservationConflict,                            // 0x083
	FormatInProgress,                               // 0x084
	CompletionQueueInvalid,                         // 0x100
	InvalidQueueIdentifier,                         // 0x101
	InvalidQueueSize,                               // 0x102
	AbortCommandLimitExceeded,                      // 0x103
	AsynchronousEventRequestLimitExceeded,          // 0x105
	InvalidFirmwareSlot,                            // 0x106
	InvalidFirmwareImage,                           // 0x107
	InvalidInterruptVector,                         // 0x108
	InvalidLogPage,                                 // 0x109
	InvalidFormat,                                  // 0x10a
	FirmwareActivationRequiresConventionalReset,    // 0x10b
	InvalidQueueDeletion,                           // 0x10c
	FeatureIdentifierNotSaveable,                   // 0x10d
	FeatureNotChangeable,                           // 0x10e
	FeatureNotNamespaceSpecific,                    // 0x10f
	FirmwareActivationRequiresNvmSubsystemReset,    // 0x110
	FirmwareActivationRequiresReset,                // 0x111
	FirmwareActivationRequiresMaximumTimeViolation, // 0x112
	FirmwareActivationProhibited,                   // 0x113
	OverlappingRange,                               // 0x114
	NamespaceInsufficientCapacity,                  // 0x115
	NamespaceIdentifierUnavailable,                 // 0x116
	NamespaceAlreadyAttached,                       // 0x118
	NamespaceIsPrivate,                             // 0x119
	NamespaceNotAttached,                           // 0x11a
	ThinProvisioningNotSupported,                   // 0x11b
	ControllerListInvalid,                          // 0x11c
	ConflictingAttributes,                          // 0x180
	InvalidProtectionInformation,                   // 0x181
	AttemptedWriteToReadOnlyRange,                  // 0x182
	WriteFault,                                     // 0x280
	UnrecoveredReadError,                           // 0x281
	EndToEndGuardCheckError,                        // 0x282
	EndToEndApplicationTagCheckError,               // 0x283
	EndToEndReferenceTagCheckError,                 // 0x284
	CompareFailure,                                 // 0x285
	AccessDenied,                                   // 0x286
	DeallocatedOrUnwrittenLogicalBlock,             // 0x287
	UnknownGenericStatus(u16),
	UnknownCommandSpecificStatus(u16),
	UnknownIntegrityError(u16),
	UnknownVendorSpecificStatus(u16),
	UnknownStatus(u16),
}

impl From<u16> for StatusCode {
	fn from(status: u16) -> StatusCode {
		use self::StatusCode::*;
		match status & 0x7ff {
			0x000 => SuccessfulCompletion,
			0x001 => InvalidCommandOpcode,
			0x002 => InvalidFieldInCommand,
			0x003 => CommandIdConflict,
			0x004 => DataTransferError,
			0x005 => CommandsAbortedDueToPowerLossNotification,
			0x006 => InternalError,
			0x007 => CommandAbortRequested,
			0x008 => CommandAbortedDueToSqDeletion,
			0x009 => CommandAbortedDueToFailedFusedCommand,
			0x00a => CommandAbortedDueToMissingFusedCommand,
			0x00b => InvalidNamespaceOrFormat,
			0x00c => CommandSequenceError,
			0x00d => InvalidSglSegmentDescriptor,
			0x00e => InvalidNumberOfSglDescriptors,
			0x00f => DataSglLengthInvalid,
			0x010 => MetadataSglLengthInvalid,
			0x011 => SglDescriptorTypeInvalid,
			0x012 => InvalidUseOfControllerMemoryBuffer,
			0x013 => PrpOffsetInvalid,
			0x014 => AtomicWriteUnitExceeded,
			0x016 => SglOffsetInvalid,
			0x017 => SglSubTypeInvalid,
			0x018 => HostIdentifierInconsistentFormat,
			0x019 => KeepAliveTimeoutExpired,
			0x01a => KeepAliveTimeoutInvalid,
			0x080 => LbaOutOfRange,
			0x081 => CapacityExceeded,
			0x082 => NamespaceNotReady,
			0x083 => ReservationConflict,
			0x084 => FormatInProgress,
			0x100 => CompletionQueueInvalid,
			0x101 => InvalidQueueIdentifier,
			0x102 => InvalidQueueSize,
			0x103 => AbortCommandLimitExceeded,
			0x105 => AsynchronousEventRequestLimitExceeded,
			0x106 => InvalidFirmwareSlot,
			0x107 => InvalidFirmwareImage,
			0x108 => InvalidInterruptVector,
			0x109 => InvalidLogPage,
			0x10a => InvalidFormat,
			0x10b => FirmwareActivationRequiresConventionalReset,
			0x10c => InvalidQueueDeletion,
			0x10d => FeatureIdentifierNotSaveable,
			0x10e => FeatureNotChangeable,
			0x10f => FeatureNotNamespaceSpecific,
			0x110 => FirmwareActivationRequiresNvmSubsystemReset,
			0x111 => FirmwareActivationRequiresReset,
			0x112 => FirmwareActivationRequiresMaximumTimeViolation,
			0x113 => FirmwareActivationProhibited,
			0x114 => OverlappingRange,
			0x115 => NamespaceInsufficientCapacity,
			0x116 => NamespaceIdentifierUnavailable,
			0x118 => NamespaceAlreadyAttached,
			0x119 => NamespaceIsPrivate,
			0x11a => NamespaceNotAttached,
			0x11b => ThinProvisioningNotSupported,
			0x11c => ControllerListInvalid,
			0x180 => ConflictingAttributes,
			0x181 => InvalidProtectionInformation,
			0x182 => AttemptedWriteToReadOnlyRange,
			0x280 => WriteFault,
			0x281 => UnrecoveredReadError,
			0x282 => EndToEndGuardCheckError,
			0x283 => EndToEndApplicationTagCheckError,
			0x284 => EndToEndReferenceTagCheckError,
			0x285 => CompareFailure,
			0x286 => AccessDenied,
			0x287 => DeallocatedOrUnwrittenLogicalBlock,
			status @ 0x000...0x0ff => UnknownGenericStatus(status),
			status @ 0x100...0x1ff => UnknownCommandSpecificStatus(status),
			status @ 0x200...0x2ff => UnknownIntegrityError(status),
			status @ 0x700...0x7ff => UnknownVendorSpecificStatus(status),
			status @ _ => UnknownStatus(status),
		}
	}
}

pub mod identify {
	use byteorder::{LittleEndian, ReadBytesExt};

	pub struct IdentifyController([u8; 4096]);

	impl From<[u8; 4096]> for IdentifyController {
		fn from(array: [u8; 4096]) -> Self {
			IdentifyController(array)
		}
	}

	impl IdentifyController {
		pub fn vid(&self) -> u16 {
			(&self.0[0..2]).read_u16::<LittleEndian>().unwrap()
		}

		pub fn ssvid(&self) -> u16 {
			(&self.0[2..4]).read_u16::<LittleEndian>().unwrap()
		}

		pub fn sn(&self) -> &[u8] {
			&self.0[4..24]
		}

		pub fn mn(&self) -> &[u8] {
			&self.0[24..64]
		}

		pub fn fr(&self) -> &[u8] {
			&self.0[64..72]
		}

		pub fn oacs(&self) -> Oacs {
			Oacs::from_bits_truncate((&self.0[256..258]).read_u16::<LittleEndian>().unwrap())
		}
	}

	bitflags! {
		pub struct Oacs: u16 {
			const SECURITY       = 0x0001;
			const FORMAT         = 0x0002;
			const FIRMWARE       = 0x0004;
			const NAMESPACE      = 0x0008;
			const RESERVED1      = 0x0010;
			const RESERVED2      = 0x0020;
			const RESERVED3      = 0x0040;
			const RESERVED4      = 0x0080;
			const RESERVED5      = 0x0100;
			const RESERVED6      = 0x0200;
			const RESERVED7      = 0x0400;
			const RESERVED8      = 0x0800;
			const RESERVED9      = 0x1000;
			const RESERVED10     = 0x2000;
			const RESERVED11     = 0x4000;
			const RESERVED12     = 0x8000;
		}
	}
}

pub mod security {
	use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
	use std::io::Write;

	#[derive(Debug, PartialEq, Eq)]
	pub enum Protocol {
		Info,                        // 0x00
		Tcg(u8),                     // 0x01 ... 0x06
		CbCs,                        // 0x07
		TapeDataEncryption,          // 0x20
		DataEncryptionConfiguration, // 0x21
		SaCreationCapabilities,      // 0x40
		IkeV2Scsi,                   // 0x41
		Nvme,                        // 0xea
		JedecUniversalFlashStorage,  // 0xec
		SdCardTrusteFlash,           // 0xed
		Ieee1667,                    // 0xee
		AtaSecurity,                 // 0xef
		Vendor(u8),                  // 0xf0 ... 0xff
		Other(u8),
	}

	impl From<u8> for Protocol {
		fn from(prot: u8) -> Protocol {
			use self::Protocol::*;
			match prot {
				0x00 => Info,
				0x01...0x06 => Tcg(prot),
				0x07 => CbCs,
				0x20 => TapeDataEncryption,
				0x21 => DataEncryptionConfiguration,
				0x40 => SaCreationCapabilities,
				0x41 => IkeV2Scsi,
				0xea => Nvme,
				0xec => JedecUniversalFlashStorage,
				0xed => SdCardTrusteFlash,
				0xee => Ieee1667,
				0xef => AtaSecurity,
				0xf0...0xff => Vendor(prot),
				_ => Other(prot),
			}
		}
	}

	impl Into<u8> for Protocol {
		fn into(self) -> u8 {
			use self::Protocol::*;
			match self {
				Info => 0x00,
				CbCs => 0x07,
				TapeDataEncryption => 0x20,
				DataEncryptionConfiguration => 0x21,
				SaCreationCapabilities => 0x40,
				IkeV2Scsi => 0x41,
				Nvme => 0xea,
				JedecUniversalFlashStorage => 0xec,
				SdCardTrusteFlash => 0xed,
				Ieee1667 => 0xee,
				AtaSecurity => 0xef,
				Tcg(prot) | Vendor(prot) | Other(prot) => prot,
			}
		}
	}

	#[repr(u16)]
	#[allow(dead_code)]
	pub enum SecurityProtocolInformationSpecific {
		SupportedProtocols = 0,
		CertificateData = 1,
	}

	pub struct AtaSecurityIdentify([u8; 16]);

	impl From<[u8; 16]> for AtaSecurityIdentify {
		fn from(array: [u8; 16]) -> Self {
			assert_eq!(array[1], 0xe);
			AtaSecurityIdentify(array)
		}
	}

	impl AtaSecurityIdentify {
		pub fn security_erase_time(&self) -> u16 {
			(&self.0[2..4]).read_u16::<BigEndian>().unwrap()
		}

		pub fn enhanced_security_erase_time(&self) -> u16 {
			(&self.0[4..6]).read_u16::<BigEndian>().unwrap()
		}

		pub fn master_password_identifier(&self) -> u16 {
			(&self.0[6..8]).read_u16::<BigEndian>().unwrap()
		}

		pub fn maxset(&self) -> bool {
			const MAXSET: u8 = 0x01;
			(self.0[8] & MAXSET) == MAXSET
		}

		pub fn s_suprt(&self) -> bool {
			const S_SUPRT: u8 = 0x01;
			(self.0[9] & S_SUPRT) == S_SUPRT
		}

		pub fn s_enabld(&self) -> bool {
			const S_ENABLD: u8 = 0x02;
			(self.0[9] & S_ENABLD) == S_ENABLD
		}

		pub fn locked(&self) -> bool {
			const LOCKED: u8 = 0x04;
			(self.0[9] & LOCKED) == LOCKED
		}

		pub fn frozen(&self) -> bool {
			const FROZEN: u8 = 0x08;
			(self.0[9] & FROZEN) == FROZEN
		}

		pub fn pwncntex(&self) -> bool {
			const PWCNTEX: u8 = 0x10;
			(self.0[9] & PWCNTEX) == PWCNTEX
		}

		pub fn en_er_sup(&self) -> bool {
			const EN_ER_SUP: u8 = 0x20;
			(self.0[9] & EN_ER_SUP) == EN_ER_SUP
		}
	}

	#[repr(u16)]
	pub enum AtaSecuritySpecific {
		SetPassword = 1,     // flag = maximum security?
		Unlock = 2,          // no flag
		ErasePrepare = 3,    // no data
		EraseUnit = 4,       // flag = enhanced erase?
		FreezeLock = 5,      // no data
		DisablePassword = 6, // no flag
	}

	#[repr(packed)]
	pub struct AtaSecurityPassword([u8; 36]);

	impl AtaSecurityPassword {
		pub fn new(
			password: [u8; 32],
			master_password: bool,
			flag: Option<bool>,
			master_password_id: Option<u16>,
		) -> AtaSecurityPassword {
			let mut buf = [0u8; 36];
			{
				let mut ptr = &mut buf[..];
				ptr.write_u8(flag.unwrap_or(false) as u8).unwrap();
				ptr.write_u8(master_password as u8).unwrap();
				ptr.write_all(&password).unwrap();
				ptr.write_u16::<BigEndian>(master_password_id.unwrap_or(0))
					.unwrap();
			}
			AtaSecurityPassword(buf)
		}
	}

	impl Into<[u8; 36]> for AtaSecurityPassword {
		fn into(self) -> [u8; 36] {
			self.0
		}
	}
}
