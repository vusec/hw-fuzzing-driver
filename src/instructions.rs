use std::iter::{zip, Flatten};

pub type EncodedInstruction = u32;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ArgumentSpec {
    name: &'static str,
    length: u32,
    offset: u32,
}

/// Specifies a single
impl ArgumentSpec {
    pub fn new(name: &'static str, length: u32, offset: u32) -> Self {
        Self {
            name,
            length,
            offset,
        }
    }

    pub fn extract(&'static self, inst: EncodedInstruction) -> Argument {
        let mask: u32 = 2u32.pow(self.length) - 1u32;
        let value: u32 = (inst >> self.offset) & mask;
        Argument { spec: self, value }
    }

    pub fn length(&self) -> u32 {
        self.length
    }

    pub fn max_value(&self) -> u32 {
        2u32.pow(self.length)
    }

    pub fn name(&self) -> &str {
        self.name
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct InstructionTemplate {
    name: &'static str,
    match_pattern: EncodedInstruction,
    mask_pattern: EncodedInstruction,
    operand1: Option<&'static ArgumentSpec>,
    operand2: Option<&'static ArgumentSpec>,
    operand3: Option<&'static ArgumentSpec>,
    operand4: Option<&'static ArgumentSpec>,
    operand5: Option<&'static ArgumentSpec>,
}

impl InstructionTemplate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: &'static str,
        match_pattern: EncodedInstruction,
        mask_pattern: EncodedInstruction,
        operand1: Option<&'static ArgumentSpec>,
        operand2: Option<&'static ArgumentSpec>,
        operand3: Option<&'static ArgumentSpec>,
        operand4: Option<&'static ArgumentSpec>,
        operand5: Option<&'static ArgumentSpec>,
    ) -> Self {
        Self {
            name,
            match_pattern,
            mask_pattern,
            operand1,
            operand2,
            operand3,
            operand4,
            operand5,
        }
    }

    pub fn operands(&self) -> Flatten<std::array::IntoIter<&Option<&'static ArgumentSpec>, 5>> {
        [
            &self.operand1,
            &self.operand2,
            &self.operand3,
            &self.operand4,
            &self.operand5,
        ]
        .into_iter()
        .flatten()
    }

    pub fn base_pattern(&self) -> EncodedInstruction {
        self.match_pattern
    }

    pub fn name(&self) -> &str {
        self.name
    }

    pub fn op_with_name(&self, name: String) -> Option<&'static ArgumentSpec> {
        for op in self.operands() {
            if op.name() == name {
                return Some(op);
            }
        }
        None
    }

    pub fn matches(&self, data: EncodedInstruction) -> bool {
        data & self.mask_pattern == self.match_pattern
    }

    pub fn decode(&'static self, data: EncodedInstruction) -> Option<Instruction> {
        if !self.matches(data) {
            return None;
        }

        let mut args = Vec::<Argument>::new();
        for arg in self.operands() {
            args.push(arg.extract(data))
        }
        Some(Instruction {
            template: self,
            arguments: args,
        })
    }
}

include!(concat!(env!("OUT_DIR"), "/raw_instructions.rs"));

pub mod sets {
    use super::riscv::*;
    use super::InstructionTemplate;

    pub fn riscv_g() -> Vec<&'static InstructionTemplate> {
        let mut result = Vec::<&'static InstructionTemplate>::new();
        result.append(&mut rv64_i::INSTS.to_vec());
        result.append(&mut rv64_a::INSTS.to_vec());
        result.append(&mut rv64_d::INSTS.to_vec());
        result.append(&mut rv64_f::INSTS.to_vec());
        result.append(&mut rv64_m::INSTS.to_vec());
        result.append(&mut rv_i::INSTS.to_vec());
        result.append(&mut rv_a::INSTS.to_vec());
        result.append(&mut rv_d::INSTS.to_vec());
        result.append(&mut rv_f::INSTS.to_vec());
        result.append(&mut rv_m::INSTS.to_vec());
        result
    }

    pub fn riscv_base() -> Vec<&'static InstructionTemplate> {
        let mut result = Vec::<&'static InstructionTemplate>::new();
        result.append(&mut rv64_i::INSTS.to_vec());
        result.append(&mut rv_i::INSTS.to_vec());
        result
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Argument {
    spec: &'static ArgumentSpec,
    value: u32,
}

impl Argument {
    pub fn encode(&self) -> EncodedInstruction {
        self.value << self.spec.offset
    }
    pub fn new(spec: &'static ArgumentSpec, value: u32) -> Argument {
        Argument { spec, value }
    }
    pub fn spec(&self) -> &'static ArgumentSpec {
        self.spec
    }

    pub fn value(&self) -> u32 {
        self.value
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Instruction {
    template: &'static InstructionTemplate,
    arguments: Vec<Argument>,
}

impl Instruction {
    pub fn encode(&self) -> EncodedInstruction {
        let mut result: EncodedInstruction = self.template.base_pattern();
        for arg in &self.arguments {
            result |= arg.encode()
        }
        result
    }

    pub fn new(template: &'static InstructionTemplate, arguments: Vec<Argument>) -> Instruction {
        // Check that the arguments match the template's arguments.
        debug_assert_eq!(template.operands().count(), arguments.len());
        for i in zip(
            arguments.clone().into_iter(),
            template.operands().into_iter(),
        ) {
            debug_assert_eq!(i.0.spec.name, i.1.name);
        }

        Instruction {
            template,
            arguments,
        }
    }

    pub fn arguments(&self) -> &[Argument] {
        self.arguments.as_ref()
    }

    pub fn template(&self) -> &'static InstructionTemplate {
        self.template
    }

    pub fn set_arg(&mut self, new_arg: Argument) {
        // Delete the old argument if it exists.
        self.arguments
            .retain(|arg: &Argument| arg.spec != new_arg.spec);
        // Add the new argument at the end.
        self.arguments.push(new_arg);
    }
}

#[cfg(test)]
mod tests {
    use crate::instructions::riscv::args;
    use crate::instructions::riscv::rv_i::*;
    use crate::instructions::*;

    #[test]
    fn encode_add() {
        let inst = Instruction::new(
            &ADD,
            vec![
                Argument::new(&args::RD, 1),
                Argument::new(&args::RS1, 2),
                Argument::new(&args::RS2, 4),
            ],
        );
        assert_eq!(inst.encode(), 0x004100b3);
    }

    #[test]
    fn compare_inst() {
        let inst1 = Instruction::new(
            &ADD,
            vec![
                Argument::new(&args::RD, 1),
                Argument::new(&args::RS1, 2),
                Argument::new(&args::RS2, 4),
            ],
        );
        let inst2 = Instruction::new(
            &ADD,
            vec![
                Argument::new(&args::RD, 1),
                Argument::new(&args::RS1, 2),
                Argument::new(&args::RS2, 4),
            ],
        );
        assert!(inst1 == inst2);
    }

    #[test]
    fn encode_add_all_args() {
        let inst = Instruction::new(
            &ADD,
            vec![
                Argument::new(&args::RD, 1),
                Argument::new(&args::RS1, 2),
                Argument::new(&args::RS2, 4),
            ],
        );
        assert_eq!(inst.encode(), 0x004100B3);

        // Do a whole decode-encode roundabout with this instruction.
        assert_eq!(ADD.decode(inst.encode()).unwrap(), inst);
    }
}
