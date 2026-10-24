//! Prints the lifted p-code for a hex byte string: `pcode_dump <lang> <hex> [addr]`.
use sleigh_runtime::Runtime;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let lang = ra_sleigh::Language::load(&ra_sleigh::default_processors_dir(), &args[1]).unwrap();
    let bytes: Vec<u8> = (0..args[2].len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&args[2][i..i + 2], 16).unwrap())
        .collect();
    let addr = args
        .get(3)
        .map(|a| u64::from_str_radix(a.trim_start_matches("0x"), 16).unwrap())
        .unwrap_or(0x1000);
    let mut rt = Runtime::new(lang.initial_ctx);
    rt.decode(&lang.sleigh, addr, &bytes).expect("decode");
    println!("{}", rt.disasm(&lang.sleigh).unwrap_or("?"));
    let block = rt.lift(&lang.sleigh).unwrap().clone();
    for op in &block.instructions {
        println!("  {:?}    // {:?} {:?}", op, op.op, op.inputs.get());
    }
    println!("{:?}", lang.decoder().decode(addr, &bytes));
}
