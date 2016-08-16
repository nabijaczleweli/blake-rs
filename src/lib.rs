//! An implementation of the [BLAKE hash function](http://131002.net/blake), via FFI to reference implementation.
//!
//! For more information about BLAKE visit its [official homepage](http://131002.net/blake).
//!
//! There are two APIs provided: one for single-chunk hashing and one for hashing of multiple data segments.
//!
//! # Examples
//!
//! Hashing a single chunk of data with a 256-bit BLAKE hash function, then verifying the result.
//!
//! ```
//! extern crate blake;
//! # use std::iter::FromIterator;
//!
//! let mut result = [0; 32];
//! blake::hash(256, b"The lazy fox jumps over the lazy dog", &mut result).unwrap();
//!
//! assert_eq!(Vec::from_iter(result.iter().map(|&i| i)),
//!            vec![0x1B, 0x59, 0x7C, 0x7A, 0x88, 0x9F, 0xCE, 0xB1,
//!                 0xCC, 0x75, 0x6D, 0x6C, 0x6C, 0x06, 0xA7, 0xF9,
//!                 0x22, 0x5E, 0x02, 0xBB, 0x0C, 0x02, 0x6E, 0x8B,
//!                 0xC5, 0xEB, 0x4E, 0xA7, 0x61, 0x0E, 0xBB, 0x9E]);
//! ```
//!
//! Hashing multiple chunks of data with a 512-bit BLAKE hash function, then verifying the result.
//!
//! ```
//! extern crate blake;
//! # use std::iter::FromIterator;
//!
//! let mut result = [0; 64];
//! let state = blake::Blake::new(512).unwrap();
//!
//! state.update("Zażółć ".as_bytes());
//! state.update("gęślą ".as_bytes());
//! state.update("jaźń".as_bytes());
//!
//! state.finalise(&mut result);
//! assert_eq!(Vec::from_iter(result.iter().map(|&i| i)),
//!            vec![0x34, 0x43, 0xD3, 0x15, 0x00, 0x60, 0xFE, 0x8D,
//!                 0xBB, 0xB1, 0x21, 0x74, 0x87, 0x7B, 0x8A, 0xA2,
//!                 0x67, 0x19, 0xED, 0xC9, 0x66, 0xD6, 0xEC, 0xB5,
//!                 0x8F, 0x94, 0xBD, 0xE3, 0x5A, 0xD8, 0x96, 0x99,
//!                 0xEA, 0x03, 0xEB, 0xC2, 0x0E, 0x2B, 0xCD, 0x80,
//!                 0x5C, 0x0B, 0x09, 0x95, 0x6A, 0x1E, 0xEE, 0x3D,
//!                 0x1F, 0x07, 0x2B, 0x33, 0x64, 0x47, 0x15, 0x68,
//!                 0x10, 0x9E, 0x43, 0xC4, 0x0C, 0xE1, 0x27, 0xDA]);
//! ```
//!
//! Comparing result of single- and multi-chunk hash methods hashing the same effective message with a 384-bit BLAKE hash
//! function.
//!
//! ```
//! extern crate blake;
//! # use std::iter::FromIterator;
//!
//! let mut result_multi  = [0; 48];
//! let mut result_single = [0; 48];
//!
//! let state = blake::Blake::new(384).unwrap();
//! state.update("Zażółć ".as_bytes());
//! state.update("gęślą ".as_bytes());
//! state.update("jaźń".as_bytes());
//! state.finalise(&mut result_multi);
//!
//! blake::hash(384, "Zażółć gęślą jaźń".as_bytes(), &mut result_single).unwrap();
//!
//! assert_eq!(Vec::from_iter(result_multi .iter().map(|&i| i)),
//!            Vec::from_iter(result_single.iter().map(|&i| i)));
//! ```

extern crate libc;

mod native;

use std::error::Error;
use std::fmt;


/// Helper result type containing `BlakeError`.
pub type Result<T> = std::result::Result<T, BlakeError>;


/// Hash all data in one fell swoop.
///
/// Refer to individual functions for extended documentation.
///
/// # Example
///
/// ```
/// # extern crate blake;
/// # use std::iter::FromIterator;
/// let mut result_256 = [0; 32];
/// let mut result_512 = [0; 64];
///
/// blake::hash(256, &[], &mut result_256).unwrap();
/// blake::hash(512, &[], &mut result_512).unwrap();
///
/// assert_eq!(Vec::from_iter(result_256.iter().map(|&i| i)),
///            vec![0x71, 0x6F, 0x6E, 0x86, 0x3F, 0x74, 0x4B, 0x9A,
///                 0xC2, 0x2C, 0x97, 0xEC, 0x7B, 0x76, 0xEA, 0x5F,
///                 0x59, 0x08, 0xBC, 0x5B, 0x2F, 0x67, 0xC6, 0x15,
///                 0x10, 0xBF, 0xC4, 0x75, 0x13, 0x84, 0xEA, 0x7A]);
/// assert_eq!(Vec::from_iter(result_512.iter().map(|&i| i)),
///            vec![0xA8, 0xCF, 0xBB, 0xD7, 0x37, 0x26, 0x06, 0x2D,
///                 0xF0, 0xC6, 0x86, 0x4D, 0xDA, 0x65, 0xDE, 0xFE,
///                 0x58, 0xEF, 0x0C, 0xC5, 0x2A, 0x56, 0x25, 0x09,
///                 0x0F, 0xA1, 0x76, 0x01, 0xE1, 0xEE, 0xCD, 0x1B,
///                 0x62, 0x8E, 0x94, 0xF3, 0x96, 0xAE, 0x40, 0x2A,
///                 0x00, 0xAC, 0xC9, 0xEA, 0xB7, 0x7B, 0x4D, 0x4C,
///                 0x2E, 0x85, 0x2A, 0xAA, 0xA2, 0x5A, 0x63, 0x6D,
///                 0x80, 0xAF, 0x3F, 0xC7, 0x91, 0x3E, 0xF5, 0xB8]);
/// ```
pub fn hash(hashbitlen: i32, data: &[u8], hashval: &mut [u8]) -> Result<()> {
    match unsafe { native::Hash(hashbitlen, data.as_ptr(), data.len() as u64 * 8, hashval.as_mut_ptr()) } {
        0 => Ok(()),
        e => Err(BlakeError::from(e)),
    }
}

/// Hashing state for multiple data sets.
///
/// # Example
///
/// Hashing a string split into multiple chunks.
///
/// ```
/// # extern crate blake;
/// # use std::iter::FromIterator;
/// let state = blake::Blake::new(256).unwrap();
///
/// state.update(b"Abolish ");
/// state.update(b"the ");
/// state.update(b"bourgeoisie");
/// state.update(b"!");
///
/// let mut result = [0; 32];
/// state.finalise(&mut result);
/// assert_eq!(Vec::from_iter(result.iter().map(|&i| i)),
///            vec![0x35, 0xBF, 0x9C, 0x70, 0xFF, 0x63, 0xF1, 0x26,
///                 0x6A, 0xE7, 0x2C, 0xC9, 0x94, 0x6F, 0x59, 0xBB,
///                 0x0B, 0x21, 0xD8, 0xCC, 0x8E, 0x4D, 0xBB, 0x53,
///                 0x24, 0xDF, 0x10, 0xB7, 0x11, 0xF9, 0x82, 0x1C]);
/// ```
pub struct Blake {
    raw_state: native::FFIHashState,
}

/// Some functions in the library can fail, this enum represents all the possible ways they can.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum BlakeError {
    /// Generic failure state
    Fail,
    /// `hashbitlen` passed to `Blake::new()` or `hash()` incorrect
    BadHashbitlen,
}


impl Blake {
    /// Create a new hash state and initialise it with the given bit length.
    ///
    /// `hashbitlen` is the hash output length. <br />
    /// Valid values:
    ///
    ///   * `224`,
    ///   * `256`,
    ///   * `384`,
    ///   * `512`.
    ///
    /// Returns:
    ///
    ///   * `Err(BlakeError::BadHashbitlen)` if `hashbitlen` is not any of the mentioned above, or
    ///   * `Ok(Blake)` if initialisation succeeds.
    ///
    /// # Examples
    ///
    /// Incorrect `hashbitlen`
    ///
    /// ```
    /// # extern crate blake;
    /// assert_eq!(blake::Blake::new(0).map(|_| ()), Err(blake::BlakeError::BadHashbitlen));
    /// ```
    ///
    /// Creating a 512-long state
    ///
    /// ```
    /// # extern crate blake;
    /// blake::Blake::new(512).unwrap();
    /// ```
    pub fn new(hashbitlen: i32) -> Result<Blake> {
        let mut raw_state = native::malloc_hash_state();

        match unsafe { native::Init(raw_state, hashbitlen) } {
            0 => Ok(Blake { raw_state: raw_state }),
            e => {
                native::free_hash_state(&mut raw_state);
                Err(BlakeError::from(e))
            }
        }
    }

    /// Add a salt to the hash function.
    ///
    /// Returns:
    ///
    ///   * `Err(BlakeError::Fail)` if called after `Blake::update()`, or
    ///   * `Ok(())`, if called before `Blake::update()`.
    ///
    /// The salt's length depends on the hash function's length.
    ///
    /// |hash function length|salt length|
    /// |--------------------|-----------|
    /// |      224 bits      |  128 bits |
    /// |      256 bits      |  128 bits |
    /// |      384 bits      |  256 bits |
    /// |      512 bits      |  256 bits |
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate blake;
    /// # use std::iter::FromIterator;
    /// let mut result_unsalted = [0; 64];
    /// let mut result_salted   = [0; 64];
    ///
    /// let state_unsalted = blake::Blake::new(512).unwrap();
    /// let state_salted   = blake::Blake::new(512).unwrap();
    ///
    /// state_salted.add_salt(b"Violent  murder  of  the  proles").unwrap();
    ///
    /// state_unsalted.update(&[]);
    /// state_salted  .update(&[]);
    ///
    /// state_unsalted.finalise(&mut result_unsalted);
    /// state_salted  .finalise(&mut result_salted);
    ///
    /// assert!(Vec::from_iter(result_unsalted.iter().map(|&i| i)) !=
    ///         Vec::from_iter(result_salted  .iter().map(|&i| i)))
    /// ```
    pub fn add_salt(&self, salt: &[u8]) -> Result<()> {
        match unsafe { native::AddSalt(self.raw_state, salt.as_ptr()) } {
            0 => Ok(()),
            e => Err(BlakeError::from(e)),
        }
    }

    /// Append the provided data to the hash function.
    ///
    /// # Examples
    ///
    /// Hashing a part of [a short story](http://nabijaczleweli.xyz/capitalism/writing/Świat_to_kilka_takich_pokoi/)
    ///
    /// ```
    /// # extern crate blake;
    /// # use std::iter::FromIterator;
    /// let mut result = [0; 64];
    ///
    /// let state = blake::Blake::new(512).unwrap();
    /// state.update("    Serbiańcy znowu się pochlali, ale w sumie".as_bytes());
    /// state.update("czegoż się po wschodnich słowianach spodziewać, swoją".as_bytes());
    /// state.update("drogą. I, jak to wszystkim homo sapiensom się dzieje".as_bytes());
    /// state.update("filozofować poczęli.".as_bytes());
    /// state.finalise(&mut result);
    ///
    /// assert_eq!(Vec::from_iter(result.iter().map(|&i| i)),
    ///            vec![0xA2, 0x30, 0x50, 0x18, 0x10, 0x0D, 0x53, 0x61,
    ///                 0xC2, 0x2D, 0x61, 0x0A, 0x23, 0x4E, 0xA5, 0x28,
    ///                 0x18, 0x89, 0xA6, 0x44, 0x6E, 0xE1, 0xC4, 0x8A,
    ///                 0xDF, 0xD0, 0x6A, 0xDB, 0x1C, 0x00, 0x06, 0xA9,
    ///                 0x05, 0x0A, 0xCE, 0xB3, 0x43, 0x14, 0xB8, 0xB0,
    ///                 0x3F, 0xA3, 0xB7, 0x70, 0x5D, 0xFC, 0x14, 0xB9,
    ///                 0xAA, 0xCA, 0xDC, 0x5B, 0x34, 0x96, 0x0B, 0x3C,
    ///                 0x87, 0x1F, 0x69, 0x46, 0xCD, 0xC2, 0xB2, 0x14]);
    /// ```
    pub fn update(&self, data: &[u8]) {
        unsafe {
            native::Update(self.raw_state, data.as_ptr(), data.len() as u64 * 8);
        }
    }


    /// Finish hashing and store the output result in the provided space.
    ///
    /// The provided space must not be smaller than the hash function's size,
    /// if the provided space is smaller than the hash function's size, the behaviour is undefined.
    ///
    /// # Examples
    ///
    /// Storing and verifying results of all possible sizes.
    ///
    /// ```
    /// # extern crate blake;
    /// # use std::iter::FromIterator;
    /// let mut result_224 = [0; 28];
    /// let mut result_256 = [0; 32];
    /// let mut result_384 = [0; 48];
    /// let mut result_512 = [0; 64];
    ///
    /// let state_224 = blake::Blake::new(224).unwrap();
    /// let state_256 = blake::Blake::new(256).unwrap();
    /// let state_384 = blake::Blake::new(384).unwrap();
    /// let state_512 = blake::Blake::new(512).unwrap();
    ///
    /// state_224.update(b"The lazy fox jumps over the lazy dog.");
    /// state_256.update(b"The lazy fox jumps over the lazy dog.");
    /// state_384.update(b"The lazy fox jumps over the lazy dog.");
    /// state_512.update(b"The lazy fox jumps over the lazy dog.");
    ///
    /// state_224.finalise(&mut result_224);
    /// state_256.finalise(&mut result_256);
    /// state_384.finalise(&mut result_384);
    /// state_512.finalise(&mut result_512);
    ///
    /// assert_eq!(Vec::from_iter(result_224.iter().map(|&i| i)),
    ///            vec![0x34, 0x97, 0x89, 0x0F, 0xBC, 0x6A, 0x98, 0x1C,
    ///                 0xD2, 0x21, 0x34, 0x97, 0xE4, 0xA8, 0x0A, 0x66,
    ///                 0xD6, 0x5F, 0x4C, 0x05, 0x3D, 0x71, 0x0F, 0x7E,
    ///                 0xAB, 0x81, 0xA4, 0x2F]);
    /// assert_eq!(Vec::from_iter(result_256.iter().map(|&i| i)),
    ///            vec![0xF2, 0xE5, 0xA9, 0xD0, 0x93, 0xD8, 0xAA, 0x23,
    ///                 0x4E, 0x6C, 0x54, 0x50, 0x61, 0xE8, 0x17, 0xBE,
    ///                 0x83, 0x8B, 0x57, 0xD8, 0x99, 0x8F, 0x15, 0xDF,
    ///                 0x72, 0xE1, 0x03, 0x7F, 0xBF, 0xEB, 0x4F, 0xC7]);
    /// assert_eq!(Vec::from_iter(result_384.iter().map(|&i| i)),
    ///            vec![0xDD, 0x68, 0x1E, 0x3B, 0x56, 0xE4, 0x80, 0x01,
    ///                 0x39, 0x5A, 0xF7, 0xB7, 0x36, 0x7E, 0x50, 0xD2,
    ///                 0x74, 0x61, 0x2B, 0xC8, 0xCB, 0xFB, 0x42, 0xEE,
    ///                 0x0C, 0xEC, 0x30, 0x45, 0x9C, 0x8D, 0x01, 0x66,
    ///                 0xFC, 0xB5, 0x42, 0xE2, 0x8C, 0xB0, 0x59, 0x72,
    ///                 0x8D, 0x7B, 0x0A, 0x16, 0x05, 0x4E, 0xB2, 0xEB]);
    /// assert_eq!(Vec::from_iter(result_512.iter().map(|&i| i)),
    ///            vec![0x9A, 0xD4, 0x66, 0xCF, 0x81, 0x8B, 0x46, 0x9D,
    ///                 0x29, 0x8C, 0x62, 0x00, 0xAC, 0xD3, 0x06, 0xF9,
    ///                 0xA2, 0xF4, 0xA4, 0x9E, 0x26, 0x8C, 0xA1, 0x17,
    ///                 0xB5, 0x8F, 0x37, 0x84, 0x86, 0x35, 0x1B, 0x0A,
    ///                 0x71, 0x1B, 0x60, 0xD4, 0x1B, 0x68, 0x7F, 0xD3,
    ///                 0x5F, 0x30, 0xBE, 0x2E, 0x00, 0xA8, 0x25, 0xD6,
    ///                 0x66, 0x6D, 0x9C, 0x4C, 0x23, 0xA5, 0x23, 0xD3,
    ///                 0x10, 0xA0, 0x58, 0x3F, 0x1E, 0x7C, 0xCC, 0xFE]);
    /// ```
    pub fn finalise(&self, hashval: &mut [u8]) {
        unsafe {
            native::Final(self.raw_state, hashval.as_mut_ptr());
        }
    }
}

impl Drop for Blake {
    fn drop(&mut self) {
        native::free_hash_state(&mut self.raw_state);
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
