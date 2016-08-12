use libc::{c_void, malloc, free, c_int, c_uint, c_ulonglong};
use std::ptr::null_mut;
use std::mem::size_of;


pub type FFIHashState = *mut c_void;


#[link(name = "blake")]
extern "C" {
    pub fn Init(state: FFIHashState, hashbitlen: c_int) -> c_int;
    pub fn AddSalt(state: FFIHashState, salt: *const u8) -> c_int;
    pub fn Update(state: FFIHashState, data: *const u8, databitlen: u64) -> c_int;
    pub fn Final(state: FFIHashState, hashval: *mut u8) -> c_int;

    pub fn Hash(hashbitlen: c_int, data: *const u8, databitlen: u64, hashval: *mut u8) -> c_int;
}


pub fn malloc_hash_state() -> FFIHashState {
    unsafe {
        malloc(size_of::<c_int>() * 4 + size_of::<c_uint>() * 8 + size_of::<c_uint>() * 2 + size_of::<u8>() * 64 + size_of::<c_uint>() * 4 +
               size_of::<c_ulonglong>() * 8 + size_of::<c_ulonglong>() * 2 + size_of::<u8>() * 128 + size_of::<c_ulonglong>() * 4)
    }
}

pub fn free_hash_state(state: &mut FFIHashState) {
    unsafe { free(*state) };
    *state = null_mut();
}
