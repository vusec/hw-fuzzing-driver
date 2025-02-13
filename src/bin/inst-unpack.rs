use clap::Parser;
use crossterm::style::Stylize;
use riscv_mutator::assembler::assemble_instructions;
use riscv_mutator::program_input::ProgramInput;
use std::fs;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    input: Vec<String>,
}

fn main() {
    let args = Args::parse();

    for filename in args.input {
        let buffer = fs::read(filename.clone()).expect("Failed to read file");
        let input = postcard::from_bytes::<ProgramInput>(buffer.as_slice());

        if input.is_err() {
            eprintln!("Note: File not in internal serialized format.");
            continue;
        }
        let program = input.unwrap().insts().to_vec();
        let bytes = assemble_instructions(&program);
        let output = filename + ".insts";
        fs::write(output.clone(), bytes).expect("Unable to write output file");
        println!("Written output to {}:", output.bold().blue());
    }
}
