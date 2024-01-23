mod arch;
mod error;
mod litmus;
mod output;
mod parse;

fn main() {
    let litmus_toml = std::fs::read_to_string("test.toml").unwrap();
    let parsed_litmus = parse::parse(&litmus_toml).unwrap();
    // println!("{litmus:?}");
    output::write_output(parsed_litmus).unwrap();
}
