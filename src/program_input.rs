//! The gramatron grammar fuzzer
use core::hash::{BuildHasher, Hasher};
use libafl::{
    bolts::AsSlice,
    prelude::{HasLen, HasTargetBytes, Input, OwnedSlice},
    Error,
};
use std::fmt;
use std::path::Path;

use libafl::bolts::fs::write_file_atomic;

use ahash::RandomState;
use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    assembler::assemble_instructions,
    instructions::{self, Instruction},
    parser::parse_instructions,
};

pub trait HasProgramInput {
    fn insts(&self) -> &[Instruction];
    fn insts_mut(&mut self) -> &mut Vec<Instruction>;
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct ProgramInput {
    insts: Vec<Instruction>,
    /// Raw bytes for opaque/external-generated programs that bypass instruction decoding.
    raw_bytes: Option<Vec<u8>>,
}

impl Serialize for ProgramInput {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if let Some(ref raw) = self.raw_bytes {
            serializer.serialize_bytes(raw.as_slice())
        } else {
            serializer.serialize_bytes(assemble_instructions(&self.insts).as_slice())
        }
    }
}

impl<'de> Deserialize<'de> for ProgramInput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(ProgramInputVisitor)
    }
}

impl HasTargetBytes for ProgramInput {
    fn target_bytes(&self) -> OwnedSlice<u8> {
        if let Some(ref raw) = self.raw_bytes {
            return OwnedSlice::<u8>::from(raw.clone());
        }
        let bytes = assemble_instructions(&self.insts);
        debug_assert!(parse_instructions(&bytes.to_vec(), &instructions::riscv::all()).is_ok());
        OwnedSlice::<u8>::from(bytes.to_vec())
    }
}

struct ProgramInputVisitor;
impl<'de> Visitor<'de> for ProgramInputVisitor {
    type Value = ProgramInput;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a series of bytes")
    }

    fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        match parse_instructions(&v.to_vec(), &instructions::riscv::all()) {
            Ok(insts) => Ok(ProgramInput {
                insts,
                raw_bytes: None,
            }),
            Err(_) => Ok(ProgramInput {
                insts: Vec::new(),
                raw_bytes: Some(v.to_vec()),
            }),
        }
    }
}

impl Input for ProgramInput {
    /// Write raw program bytes to disk — exactly what target_bytes() returns.
    /// Overrides the default Input::to_file() which would add Postcard framing.
    fn to_file<P>(&self, path: P) -> Result<(), Error>
    where
        P: AsRef<Path>,
    {
        write_file_atomic(path, self.target_bytes().as_slice())
    }

    /// Load program bytes from disk and reconstruct a ProgramInput.
    /// Tries to decode as instructions; falls back to opaque raw bytes.
    fn from_file<P>(path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let bytes = std::fs::read(path)?;
        match parse_instructions(&bytes, &instructions::riscv::all()) {
            Ok(insts) => Ok(ProgramInput::new(insts)),
            Err(_) => Ok(ProgramInput::from_raw_bytes(bytes)),
        }
    }

    /// Generate a name for this input
    #[must_use]
    fn generate_name(&self, _idx: usize) -> String {
        let mut hasher = RandomState::with_seeds(0, 0, 0, 0).build_hasher();
        if let Some(ref raw) = self.raw_bytes {
            hasher.write(raw.as_slice());
            format!("size:{}-hash:{:016x}", raw.len() / 4, hasher.finish())
        } else {
            hasher.write(assemble_instructions(&self.insts).as_slice());
            format!("size:{}-hash:{:016x}", self.insts().len(), hasher.finish())
        }
    }
}

impl HasLen for ProgramInput {
    fn len(&self) -> usize {
        if let Some(ref raw) = self.raw_bytes {
            raw.len() / 4
        } else {
            self.insts.len()
        }
    }
}

impl HasProgramInput for ProgramInput {
    fn insts(&self) -> &[Instruction] {
        &self.insts
    }

    fn insts_mut(&mut self) -> &mut Vec<Instruction> {
        &mut self.insts
    }
}

impl ProgramInput {
    /// Creates a new codes input using the given terminals
    #[must_use]
    pub fn new(insts: Vec<Instruction>) -> Self {
        Self { insts, raw_bytes: None }
    }

    /// Creates a new input from raw bytes, bypassing instruction decoding.
    /// Used by the external generator for opaque programs.
    #[must_use]
    pub fn from_raw_bytes(bytes: Vec<u8>) -> Self {
        Self {
            insts: Vec::new(),
            raw_bytes: Some(bytes),
        }
    }

    /// Returns true if this input holds raw (un-decoded) bytes.
    pub fn is_raw(&self) -> bool {
        self.raw_bytes.is_some()
    }

    pub fn insts(&self) -> &[Instruction] {
        &self.insts
    }

    pub fn insts_mut(&mut self) -> &mut Vec<Instruction> {
        &mut self.insts
    }

    /// Create a bytes representation of this input
    pub fn unparse(&self, bytes: &mut Vec<u8>) {
        bytes.clear();
        bytes.extend_from_slice(assemble_instructions(&self.insts).as_slice());
    }

    /// Crop the value to the given length
    pub fn crop(&self, from: usize, to: usize) -> Result<Self, Error> {
        if from < to && to <= self.insts.len() {
            let mut insts = vec![];
            insts.clone_from_slice(&self.insts[from..to]);
            Ok(Self { insts, raw_bytes: None })
        } else {
            Err(Error::illegal_argument("Invalid from or to argument"))
        }
    }
}
