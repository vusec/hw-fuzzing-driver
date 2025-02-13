use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::process::ExitCode;
use std::{env, fs};

use riscv_mutator::assembler::assemble_instructions;
use riscv_mutator::instructions::{self, Argument, Instruction, InstructionTemplate};

fn read_lines(filename: String) -> io::Lines<BufReader<File>> {
    let file = File::open(filename).unwrap();
    return io::BufReader::new(file).lines();
}

fn find_template(name: String) -> Result<&'static InstructionTemplate, String> {
    for inst in instructions::riscv::all() {
        if inst.name() == name {
            return Ok(inst);
        }
    }
    return Err(format!("Could not find instruction with name '{}'", &name));
}

fn parse_arg(inst: &'static InstructionTemplate, arg_str: String) -> Result<Argument, String> {
    let parts = arg_str.trim().split("=");

    if parts.clone().count() != 2 {
        return Err(format!("Not in ARG=VALUE format: '{}'", arg_str));
    }

    let name = parts.clone().nth(0).clone();
    let value_str_or_err = parts.clone().nth(1).clone();

    if value_str_or_err.is_none() || value_str_or_err.unwrap().is_empty() {
        return Err(format!("Missing value in arg: {}", arg_str));
    }

    let value_str = value_str_or_err.unwrap();

    let spec_or_none = inst.op_with_name(name.unwrap().to_string());
    if spec_or_none.is_none() {
        let mut msg: String = format!("Possible operands for {}:\n", inst.name());
        for op in inst.operands() {
            msg.push_str(format!("* {}\n", op.name()).as_str());
        }

        return Err(format!(
            "Failed to find operand with name {}\n{}",
            name.unwrap(),
            msg
        ));
    }
    let spec = spec_or_none.unwrap();

    let is_hex = value_str.starts_with("0x");
    let radix = if is_hex { 16 } else { 10 };

    let value_or_err = u32::from_str_radix(value_str.trim_start_matches("0x"), radix);
    if value_or_err.is_err() {
        return Err(format!("Invalid decimal or hex value: {}", value_str));
    }
    let value = value_or_err.unwrap();

    if value > spec.max_value() {
        return Err(format!(
            "Too large value {} for field {} which only allows up to {}",
            value,
            spec.name(),
            spec.max_value()
        ));
    }

    Ok(Argument::new(&spec, value))
}

fn parse_inst(line: String) -> Result<Instruction, String> {
    // Remove comments.
    let without_comment = line.split("#").nth(0).unwrap();
    let stripped = without_comment.trim();

    let mut parts = stripped.split(" ").clone();
    let name = parts.nth(0).clone();
    let inst = find_template(name.unwrap().to_string())?;

    let mut args = Vec::<Argument>::new();

    let mut seen_ops = HashSet::<String>::new();

    for arg_str in parts {
        if arg_str.trim().is_empty() {
            continue;
        }
        let arg = parse_arg(inst, arg_str.to_string());
        if arg.is_err() {
            return Err(format!(
                "Failed to parse '{}'. Reason: {}",
                arg_str,
                arg.err().unwrap()
            ));
        }
        let arg_name = arg.as_ref().unwrap().spec().name().to_string();
        if seen_ops.contains(&arg_name) {
            return Err(format!("Duplicate operand '{}'", arg_name));
        }
        seen_ops.insert(arg_name);
        args.push(arg.unwrap());
    }

    if seen_ops.len() != inst.operands().count() {
        let mut msg: String = format!("Missing operands in instruction {}:\n", inst.name());
        for op in inst.operands() {
            if seen_ops.contains(op.name()) {
                continue;
            }
            msg.push_str(format!("* {}\n", op.name()).as_str());
        }

        return Err(msg);
    }

    Ok(Instruction::new(inst, args))
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    let input = &args[1];
    let output = &args[2];

    let mut file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(output)
        .expect("Failed to open output file.");

    let mut written: u64 = 0;

    let lines = read_lines(input.to_string());
    for line_or_err in lines {
        let line = line_or_err.unwrap();
        // Skip comments.
        if line.trim().starts_with("#") || line.trim().is_empty() {
            continue;
        }
        let inst = parse_inst(line);
        if inst.is_err() {
            eprintln!("error: {}", inst.err().unwrap());
            return ExitCode::FAILURE;
        }

        let out = assemble_instructions(&vec![inst.unwrap()]);

        file.write_all(&out).expect("Failed to write output file.");
        written += 1;
    }

    println!("Wrote {} instructions", written);

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use riscv_mutator::instructions::Instruction;

    use crate::parse_inst;

    fn dump_inst(inst: &Instruction) -> String {
        let mut result = inst.template().name().to_string();
        for op in inst.arguments() {
            result += " ";
            result += op.spec().name();
            result += "=";
            result += &format!("{:#x}", op.value()).to_string();
        }
        result
    }

    #[test]
    fn assembly_add() {
        let input = "addi rd=0x1 rs1=0x1 imm12=0x3";
        let inst = parse_inst(input.to_string()).unwrap();
        assert_eq!(dump_inst(&inst), input);
    }

    fn has_error(res: Result<Instruction, String>, needle: &str) {
        assert!(res.is_err());
        let err = res.err().unwrap();
        assert!(
            err.contains(needle),
            "'{}' does not contain '{}'",
            err,
            needle
        );
    }

    #[test]
    fn assembly_invalid_inst() {
        let parse = parse_inst("addasdf".to_string());
        has_error(parse, "Could not find instruction");
    }

    #[test]
    fn assembly_double_op() {
        let parse = parse_inst("addi rd=0x1 rd=0x1 rs1=0x1 imm12=0x3".to_string());
        has_error(parse, "Duplicate operand");
    }

    #[test]
    fn assembly_invalid_format() {
        let parse = parse_inst("addi rd==0x1 rs1=0x1 imm12=0x3".to_string());
        has_error(parse, "Not in ARG=VALUE");
    }

    #[test]
    fn assembly_invalid_op() {
        let parse = parse_inst("addi rERR=0x1 rs1=0x1 imm12=0x3".to_string());
        has_error(parse, "Failed to find operand with name");
    }

    #[test]
    fn assembly_missing_op() {
        let parse = parse_inst("addi rd=0x1 rs1=0x1".to_string());
        has_error(parse, "Missing operands in instruction");
    }

    #[test]
    fn assembly_no_value() {
        let parse = parse_inst("addi rd= rs1=0x1 imm12=0x3".to_string());
        has_error(parse, "Missing value in arg");
    }

    #[test]
    fn assembly_too_large_value() {
        let parse = parse_inst("addi rd=0xfff rs1=0x1 imm12=0x3".to_string());
        has_error(parse, "Too large value ");
    }

    #[test]
    fn assembly_non_hex_value() {
        let parse = parse_inst("addi rd=0xU rs1=0x1 imm12=0x3".to_string());
        has_error(parse, "Invalid decimal or hex value: 0xU");
    }
}
