mod arch;
mod error;
mod litmus;
mod output;
mod parse;

use std::io::Write;

use clap::{CommandFactory, Parser};
use is_terminal::IsTerminal;

#[derive(Debug, Parser)]
#[command(name = "litmus-toml-translator")]
#[command(author = "thud <thud@thud.dev>")]
#[command(about = "Translate isla TOML tests for use with system-litmus-harness.")]
#[command(version = concat!("v", env!("CARGO_PKG_VERSION"), " isla@", env!("ISLA_VERSION")))]
#[command(help_template(
    "\
{before-help}{name} {version}
{author-with-newline}{about-with-newline}
{usage-heading} {usage}

{all-args}{after-help}
"
))]
struct Cli {
    #[arg(help = "input file(s) or dir of tests (instead of stdin)")]
    input: Option<Vec<std::path::PathBuf>>,
    #[arg(short, long, help = "output file or dir (default is stdout)")]
    output: Option<std::path::PathBuf>,
    #[arg(short, long, help = "allow overwriting files with output")]
    force: bool,
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn process_toml(raw_toml: String) -> error::Result<String> {
    let parsed_litmus = parse::parse(&raw_toml)?;
    output::write_output(parsed_litmus)
}

fn is_toml(p: &dyn AsRef<std::path::Path>) -> bool {
    p.as_ref().extension().filter(|ext| ext.to_str().unwrap() == "toml").is_some()
}

fn process_path(file_or_dir: &std::path::PathBuf, out_dir: &std::path::PathBuf, force: bool) -> error::Result<()> {
    if file_or_dir.is_dir() {
        let dir = file_or_dir;
        let files = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|entry| entry.is_dir() || is_toml(entry));
        if !out_dir.exists() {
            eprintln!("creating dir {:?}", out_dir);
            std::fs::create_dir_all(out_dir).unwrap();
        }
        for input in files {
            eprintln!("dir:{dir:?} input:{input:?}");
            process_path(&input, &out_dir.join(std::path::PathBuf::from(input.file_name().unwrap())), force).unwrap();
        }
    } else {
        let file = file_or_dir;
        if !is_toml(file) {
            eprintln!("skipping {file:?}");
            return Ok(());
        }
        let file_name = file.file_name().unwrap().to_string_lossy().into_owned() + ".c";
        let output_path = out_dir.with_file_name(file_name);
        if output_path.exists() && !force {
            eprintln!("file {output_path:?} exists. skipping...");
        } else {
            let toml = std::fs::read_to_string(file).unwrap();
            match process_toml(toml) {
                Ok(output_code) => {
                    eprintln!("creating file at {output_path:?}");
                    let mut f = std::fs::File::create(&output_path).unwrap();
                    eprintln!("writing process_toml({file:?}) to {output_path:?}");
                    write!(f, "{output_code}").unwrap();
                    eprintln!("successfully translated {file:?} -> {output_path:?}");
                }
                Err(e) => {
                    eprintln!("failed to translate {output_path:?} {e}");
                }
            }
        }
    }
    Ok(())
}

fn main() {
    let cli = Cli::parse();

    if let Some(out) = &cli.output {
        if out.exists() && !out.is_dir() && !cli.force {
            eprintln!("output file {out:?} exists (and is not a directory). aborting...");
            std::process::exit(1); // TODO: better exit code here? (POSIX)
        }
    }

    match cli.input {
        Some(paths) => {
            if paths.len() == 1 {
                let path = &paths[0]; //.canonicalize().unwrap();
                if let Some(out) = &cli.output {
                    process_path(path, out, cli.force).unwrap();
                } else if path.is_file() {
                    // print to stdout
                    let toml = std::fs::read_to_string(path).unwrap();
                    match process_toml(toml) {
                        Ok(output_code) => println!("{output_code}"),
                        Err(e) => eprintln!("failed to translate toml from stdin {e}"),
                    };
                } else {
                    // let parent = std::path::PathBuf::from(path.parent().unwrap());
                    process_path(path, path, cli.force).unwrap();
                }
            } else {
                for path in paths {
                    if let Some(out) = &cli.output {
                        process_path(&path, &out.join(path.file_name().unwrap()), cli.force).unwrap();
                    } else {
                        let parent = std::path::PathBuf::from(path.parent().unwrap());
                        process_path(&path, &parent, cli.force).unwrap();
                    }
                }
            }
        }
        None => {
            let stdin = std::io::stdin();
            if stdin.is_terminal() {
                Cli::command().print_help().unwrap();
            } else {
                let lines: Vec<_> = stdin.lines().map(Result::unwrap).collect();
                let toml = lines.join("\n");
                let output_code = process_toml(toml).unwrap();
                if let Some(out) = &cli.output {
                    let mut f = std::fs::File::create(out).unwrap();
                    write!(f, "{output_code}").unwrap();
                    eprintln!("successfully translated stdin -> {out:?}");
                } else {
                    println!("{output_code}");
                }
            }
        }
    }
}
