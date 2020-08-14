#![no_std]
#![no_main]
#![feature(lang_items)]
#![feature(alloc_error_handler)]
#![feature(panic_info_message)]

// Import from `core` instead of from `std` since we are in no-std mode
use core::result::Result;

// Import CKB syscalls and structures
// https://nervosnetwork.github.io/ckb-std/riscv64imac-unknown-none-elf/doc/ckb_std/index.html
use ckb_std::{
    ckb_constants::Source,
    ckb_types::{bytes::Bytes, prelude::*},
    default_alloc, entry,
    error::SysError,
    high_level::{load_cell_data, load_script, load_witness_args},
};

use blake2b_ref::{Blake2b, Blake2bBuilder};

use secp256k1::{recover, Message, RecoveryId, Signature};

const CKB_HASH_PERSONALIZATION: &[u8] = b"ckb-default-hash";

entry!(entry);
default_alloc!();

/// Program entry
fn entry() -> i8 {
    // Call main function and return error code
    match main() {
        Ok(_) => 0,
        Err(err) => err as i8,
    }
}

/// Error
#[repr(i8)]
enum Error {
    IndexOutOfBound = 100,
    ItemMissing,
    LengthNotEnough,
    Encoding,
    // Add customized errors here...
    WitnessMissInputType,
    InvalidSignature,
    PubkeyHashMismatch,
}

impl From<SysError> for Error {
    fn from(err: SysError) -> Self {
        use SysError::*;
        match err {
            IndexOutOfBound => Self::IndexOutOfBound,
            ItemMissing => Self::ItemMissing,
            LengthNotEnough(_) => Self::LengthNotEnough,
            Encoding => Self::Encoding,
            Unknown(err_code) => panic!("unexpected sys error {}", err_code),
        }
    }
}

pub fn new_blake2b() -> Blake2b {
    Blake2bBuilder::new(32)
        .personal(CKB_HASH_PERSONALIZATION)
        .build()
}

fn verify() -> Result<(), Error> {
    let witness_args = load_witness_args(0, Source::Input)?.input_type();
    if witness_args.is_none() {
        return Err(Error::WitnessMissInputType);
    }
    let witness_args: Bytes = witness_args.to_opt().unwrap().unpack();

    let messages = load_cell_data(0, Source::GroupInput)?;

    let script = load_script()?;
    let pubkey_hash: Bytes = script.args().unpack();

    let mut blake2b = new_blake2b();
    let mut message_hash = [0u8; 32];
    blake2b.update(messages.as_ref());
    blake2b.finalize(&mut message_hash);
    let sig = Signature::parse_slice(&witness_args[0..64]).unwrap();
    let rec_id = RecoveryId::parse(witness_args[64]).map_err(|_e| Error::InvalidSignature)?;
    let msg = Message::parse_slice(&message_hash).unwrap();
    let recover_pubkey = recover(&msg, &sig, &rec_id)
        .map_err(|_e| Error::InvalidSignature)?
        .serialize_compressed();

    let mut blake2b = new_blake2b();
    let mut recover_pubkey_hash = [0u8; 32];
    blake2b.update(recover_pubkey.as_ref());
    blake2b.finalize(&mut recover_pubkey_hash);
    if &recover_pubkey_hash != pubkey_hash.as_ref() {
        return Err(Error::PubkeyHashMismatch);
    }

    Ok(())
}

fn main() -> Result<(), Error> {
    verify()
}
