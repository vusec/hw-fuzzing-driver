use clap::Parser;
use colored::Colorize;
use crossterm::style::Stylize;
use riscv_mutator::instructions::Instruction;
use riscv_mutator::program_input::ProgramInput;
use riscv_mutator::{instructions, parser};
use std::fs;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    input: Vec<String>,
    #[arg(long, default_value_t = false)]
    raw: bool,
}

fn main() {
    let args = Args::parse();

    let multiple_files = args.input.len() != 1;
    for filename in args.input {
        // Print the file name when printing multiple files.
        if multiple_files {
            println!("{}:", filename.clone().bold().blue());
        }

        let buffer = fs::read(filename).expect("Failed to read file");

        let program: Vec<Instruction>;

        if args.raw {
            let program_or_err =
                parser::parse_instructions(&buffer, &instructions::sets::riscv_g());
            if program_or_err.is_err() {
                eprintln!("Failed to decode raw instructions.");
                continue;
            }
            program = program_or_err.unwrap();
        } else {
            let input = postcard::from_bytes::<ProgramInput>(buffer.as_slice());
            program = input.unwrap().insts().to_vec();
        }

        for inst in program {
            print!(" {}", Colorize::bold(inst.template().name()));
            for op in inst.arguments() {
                print!(
                    " {}={}",
                    Colorize::cyan(op.spec().name()),
                    format!("{:#x}", op.value()).red()
                );
            }
            println!("");
        }
    }
}
