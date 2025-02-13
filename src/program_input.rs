//! The gramatron grammar fuzzer
use core::hash::{BuildHasher, Hasher};
use libafl::{
    prelude::{HasLen, HasTargetBytes, Input, OwnedSlice},
    Error,
};
use std::fmt;

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
}

impl Serialize for ProgramInput {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(assemble_instructions(&self.insts).as_slice())
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
        Ok(ProgramInput {
            insts: parse_instructions(&v.to_vec(), &instructions::riscv::all()).unwrap(),
        })
    }
}

impl Input for ProgramInput {
    /// Generate a name for this input
    #[must_use]
    fn generate_name(&self, _idx: usize) -> String {
        let mut hasher = RandomState::with_seeds(0, 0, 0, 0).build_hasher();
        hasher.write(assemble_instructions(&self.insts).as_slice());
        format!("size:{}-hash:{:016x}", self.insts().len(), hasher.finish())
    }
}

impl HasLen for ProgramInput {
    fn len(&self) -> usize {
        self.insts.len()
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
        Self { insts }
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
            Ok(Self { insts })
        } else {
            Err(Error::illegal_argument("Invalid from or to argument"))
        }
    }
}
