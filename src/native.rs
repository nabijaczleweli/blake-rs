use libc::{c_void, malloc, free, c_int};
use std::ptr::null_mut;
use std::mem::size_of;


pub type FFIHashState = *mut c_void;

type BitSequence = u8;

#[repr(C)]
struct hashState {
    hashbitlen: libc::c_int,
    datalen: libc::c_int,
    init: libc::c_int,
    nullt: libc::c_int,
    h32: [u32; 8],
    t32: [u32; 2],
    data32: [BitSequence; 64],
    salt32: [u32; 4],
    h64: [u64; 8],
    t64: [u64; 2],
    data64: [BitSequence; 128],
    salt64: [u64; 4],
}

#[link(name = "blake")]
extern "C" {
    pub fn BLAKE_Hash_Init(state: FFIHashState, hashbitlen: c_int) -> c_int;
    pub fn BLAKE_Hash_AddSalt(state: FFIHashState, salt: *const u8) -> c_int;
    pub fn BLAKE_Hash_Update(state: FFIHashState, data: *const u8, databitlen: u64) -> c_int;
    pub fn BLAKE_Hash_Final(state: FFIHashState, hashval: *mut u8) -> c_int;

    pub fn BLAKE_Hash_Hash(hashbitlen: c_int, data: *const u8, databitlen: u64, hashval: *mut u8) -> c_int;
}


pub fn malloc_hash_state() -> FFIHashState {
    unsafe { malloc(size_of::<hashState>()) }
}

pub fn free_hash_state(state: &mut FFIHashState) {
    unsafe { free(*state) };
    *state = null_mut();
}
