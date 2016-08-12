extern crate libc;

mod native;

use std::error::Error;
use std::fmt;


pub type Result<T> = std::result::Result<T, BlakeError>;


pub fn hash(hashbitlen: i32, data: &[u8], hashval: &mut [u8]) -> Result<()> {
    match unsafe { native::Hash(hashbitlen, data.as_ptr(), data.len() as u64, hashval.as_mut_ptr()) } {
        0 => Ok(()),
        e => Err(BlakeError::from(e)),
    }
}


pub struct State {
    raw: native::FFIHashState,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum BlakeError {
    Fail,
    BadHashbitlen,
}


impl State {
    pub fn new(hashbitlen: i32) -> Result<State> {
        let mut raw = native::malloc_hash_state();

        match unsafe { native::Init(raw, hashbitlen) } {
            0 => Ok(State { raw: raw }),
            e => {
                native::free_hash_state(&mut raw);
                Err(BlakeError::from(e))
            }
        }
    }

    pub fn add_salt(&self, salt: &[u8]) -> Result<()> {
        match unsafe { native::AddSalt(self.raw, salt.as_ptr()) } {
            0 => Ok(()),
            e => Err(BlakeError::from(e)),
        }
    }

    pub fn update(&self, data: &[u8]) -> Result<()> {
        match unsafe { native::Update(self.raw, data.as_ptr(), data.len() as u64) } {
            0 => Ok(()),
            e => Err(BlakeError::from(e)),
        }
    }

    pub fn finalise(&self, hashval: &mut [u8]) -> Result<()> {
        match unsafe { native::Final(self.raw, hashval.as_mut_ptr()) } {
            0 => Ok(()),
            e => Err(BlakeError::from(e)),
        }
    }
}

impl Drop for State {
    fn drop(&mut self) {
        native::free_hash_state(&mut self.raw);
    }
}


impl Error for BlakeError {
    fn description(&self) -> &str {
        match self {
            &BlakeError::Fail => "Generic BLAKE fail",
            &BlakeError::BadHashbitlen => "Incorrect hashbitlen",
        }
    }
}

impl From<i32> for BlakeError {
    /// Passing incorrect error values yields unspecified behaviour.
    fn from(i: i32) -> Self {
        match i {
            0 => panic!("Not an error"),
            1 => BlakeError::Fail,
            2 => BlakeError::BadHashbitlen,
            _ => panic!("Incorrect error number"),
        }
    }
}

impl fmt::Display for BlakeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
