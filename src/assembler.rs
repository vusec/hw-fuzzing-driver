use crate::instructions::Instruction;

/// Returns a list of instructions to their encoded machine code (in bytes).
pub fn assemble_instructions(input: &Vec<Instruction>) -> Vec<u8> {
    let mut result = Vec::<u8>::new();

    for inst in input {
        for byte in inst.encode().to_le_bytes() {
            result.push(byte);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use libafl_bolts::prelude::Rand;
    use libafl_bolts::prelude::Xoshiro256StarRand;

    use crate::generator::InstGenerator;
    use crate::instructions;
    use crate::instructions::riscv::args;
    use crate::instructions::riscv::rv_i::*;
    use crate::instructions::*;
    use crate::parser::parse_instructions;

    use super::assemble_instructions;

    #[test]
    fn assemble_two_instructions() {
        let inst1 = Instruction::new(
            &ADD,
            vec![
                Argument::new(&args::RD, 1),
                Argument::new(&args::RS1, 2),
                Argument::new(&args::RS2, 4),
            ],
        );
        let inst2 = Instruction::new(
            &ADDI,
            vec![
                Argument::new(&args::RD, 3),
                Argument::new(&args::RS1, 5),
                Argument::new(&args::IMM12, 11),
            ],
        );

        let insts = vec![inst1, inst2];
        let assembled = assemble_instructions(&insts);
        // Two instructions should be 8 byte.
        assert_eq!(assembled.len(), 8);

        // Parse the output and check that we get the same result.
        let parsed = parse_instructions(&assembled, &instructions::sets::riscv_g()).unwrap();
        assert_eq!(insts, parsed);
    }

    #[test]
    fn assemble_and_parse_random_instructions() {
        for i in 0..1000 {
            let mut rng = Xoshiro256StarRand::default();
            rng.set_seed(i);

            let generator = InstGenerator::new();

            let mut insts = Vec::<Instruction>::new();

            for _ in 0..rng.below(nonzero!(5)) {
                let inst = generator.generate_instruction::<Xoshiro256StarRand>(
                    &mut rng,
                    &instructions::sets::riscv_g(),
                );
                insts.push(inst);
            }

            let assembled = assemble_instructions(&insts);

            // Parse the output and check that we get the same result.
            let parsed = parse_instructions(&assembled, &instructions::sets::riscv_g())
                .expect(format!("{}: Failed to parse instructions: {:?}", i, insts).as_str());
            assert_eq!(insts, parsed, "Instructions: {:?}", insts);
        }
    }
}
