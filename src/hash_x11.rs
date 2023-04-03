use core::{str};
use std::io;
use hashes::Error;
use hashes::{Hash as HashTrait, HashEngine as EngineTrait, hex};
use consensus;

hex_fmt_impl!(Display, Hash);
hex_fmt_impl!(LowerHex, Hash);
index_impl!(Hash);
serde_impl!(Hash, 32);
borrow_slice_impl!(Hash);

#[derive(Copy, Clone, PartialEq, Eq, Default, PartialOrd, Ord, Hash, Debug)]
#[repr(transparent)]
pub struct Hash(
    [u8; 32]
);

impl str::FromStr for Hash {
    type Err = hex::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        hex::FromHex::from_hex(s)
    }
}

impl HashTrait for Hash {
    type Engine = HashEngine;
    type Inner = [u8; 32];

    fn from_engine(e: Self::Engine) -> Self {
        println!("from_engine");
        Hash(e.midstate().into_inner())
    }

    const LEN: usize = 32;

    fn from_slice(sl: &[u8]) -> Result<Self, Error> {
        if sl.len() != 32 {
            Err(Error::InvalidLength(Self::LEN, sl.len()))
        } else {
            let mut ret = [0; 32];
            ret.copy_from_slice(sl);
            Ok(Hash(ret))
        }
    }

    fn into_inner(self) -> Self::Inner {
        self.0
    }

    fn as_inner(&self) -> &Self::Inner {
        &self.0
    }

    fn from_inner(inner: Self::Inner) -> Self {
        Hash(inner)
    }
}

#[derive(Default, Clone)]
pub struct HashEngine {
    // h: [u8; 32],
    buf: Vec<u8>,
    length: usize,
}

impl EngineTrait for HashEngine {
    type MidState = Midstate;

    fn midstate(&self) -> Self::MidState {
        println!("midstate");
        let md: Vec<u8> = rs_x11_hash::get_x11_hash(self.buf.as_slice());
        let mut h: [u8; 32] = [0; 32];
        for n in 0..32 {
            let v = md.get(n).unwrap();
            h[32-n-1] = *v;
        }
        Midstate(h)
    }

    const BLOCK_SIZE: usize = 32;

    fn input(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    fn n_bytes_hashed(&self) -> usize {
        self.length
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
pub struct Midstate(pub [u8; 32]);

index_impl!(Midstate);
serde_impl!(Midstate, 32);
borrow_slice_impl!(Midstate);

impl str::FromStr for Midstate {
    type Err = hex::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        hex::FromHex::from_hex(s)
    }
}

impl Midstate {
    /// Length of the midstate, in bytes.
    const LEN: usize = 32;

    /// Construct a new midstate from the inner value.
    pub fn from_inner(inner: [u8; 32]) -> Self {
        Midstate(inner)
    }

    /// Copies a byte slice into the [Midstate] object.
    pub fn from_slice(sl: &[u8]) -> Result<Midstate, Error> {
        if sl.len() != Self::LEN {
            Err(Error::InvalidLength(Self::LEN, sl.len()))
        } else {
            let mut ret = [0; 32];
            ret.copy_from_slice(sl);
            Ok(Midstate(ret))
        }
    }

    /// Unwraps the [Midstate] and returns the underlying byte array.
    pub fn into_inner(self) -> [u8; 32] {
        self.0
    }
}

impl hex::FromHex for Midstate {
    fn from_byte_iter<I>(iter: I) -> Result<Self, hex::Error>
        where I: Iterator<Item=Result<u8, hex::Error>> +
        ExactSizeIterator +
        DoubleEndedIterator,
    {
        Ok(Midstate::from_inner(hex::FromHex::from_byte_iter(iter.rev())?))
    }
}

impl io::Write for HashEngine {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.input(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
