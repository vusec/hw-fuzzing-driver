use crate::instructions::{Argument, ArgumentSpec, Instruction, InstructionTemplate};

/// Generates random RISC-V instructions.
#[derive(Default)]
pub struct InstGenerator {
    /// List of known arguments the generator should try to reuse.
    known_args: Vec<Argument>,
    // Chance (0-100) of reusing a known arg value in the program.
    reuse_chance: u64,
    // Chance (0-100) of choosing a power of two as arg value.
    power_of_two_chance: u64,
}

impl InstGenerator {
    pub fn new() -> Self {
        Self {
            known_args: Vec::<Argument>::new(),
            reuse_chance: 50,
            power_of_two_chance: 50,
        }
    }

    pub fn forward_args(&mut self, args: &[Argument]) {
        self.known_args.append(&mut args.to_vec())
    }

    pub fn generate_argument<R: libafl::prelude::Rand>(
        &self,
        rand: &mut R,
        arg: &'static ArgumentSpec,
    ) -> Argument {
        if rand.below(100) < self.reuse_chance {
            let filtered = self
                .known_args
                .iter()
                .filter(|x| x.spec().length() == arg.length());
            let options = filtered.collect::<Vec<&Argument>>();
            if !options.is_empty() {
                let chosen = rand.choose(options).clone();
                return Argument::new(arg, chosen.value());
            }
        }

        if rand.below(100) < self.power_of_two_chance {
            Argument::new(arg, 1 << rand.below(arg.length() as u64) as u32)
        } else {
            Argument::new(arg, rand.below(arg.max_value() as u64) as u32)
        }
    }

    pub fn generate_instruction<R: libafl::prelude::Rand>(
        &self,
        rand: &mut R,
        insts: &Vec<&'static InstructionTemplate>,
    ) -> Instruction {
        assert!(!insts.is_empty());
        let template = rand.choose(insts.iter());

        let mut arguments = Vec::<Argument>::new();
        for arg in template.operands() {
            arguments.push(self.generate_argument(rand, arg));
        }
        Instruction::new(template, arguments)
    }

    pub fn generate_instructions<R: libafl::prelude::Rand>(
        &self,
        rand: &mut R,
        insts: &Vec<&'static InstructionTemplate>,
        number: u32,
    ) -> Vec<Instruction> {
        let mut result = Vec::<Instruction>::new();
        for _ in 0..number {
            result.push(self.generate_instruction(rand, insts));
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use libafl::prelude::{Rand, Xoshiro256StarRand};

    use crate::instructions::{self, Argument};

    use super::InstGenerator;

    #[test]
    fn generate_random_instructions() {
        for i in 0..10000 {
            let mut rng = Xoshiro256StarRand::default();
            rng.set_seed(i);

            let generator = InstGenerator::new();
            let _inst = generator.generate_instruction::<Xoshiro256StarRand>(
                &mut rng,
                &instructions::sets::riscv_g(),
            );
        }
    }

    #[test]
    fn generate_instructions_and_reuse_arguments() {
        for i in 0..20 {
            let mut rng = Xoshiro256StarRand::default();
            rng.set_seed(i);

            let mut generator = InstGenerator::new();

            // Tell the generator that there it should try emit instructions
            // that use x35 as RD.
            let magic_value: u32 = 35;
            generator.forward_args(&vec![Argument::new(
                &instructions::riscv::args::RD,
                magic_value,
            )]);

            let mut found = false;
            // Generate 100 instructions and check that one of them actually
            // use x35 as RD.
            for _ in 0..100 {
                let inst = generator.generate_instruction::<Xoshiro256StarRand>(
                    &mut rng,
                    &instructions::sets::riscv_g(),
                );
                for arg in inst.arguments() {
                    if arg.spec() == &instructions::riscv::args::RD && arg.value() == magic_value {
                        found = true;
                    }
                }
            }

            assert!(found);
        }
    }
}
