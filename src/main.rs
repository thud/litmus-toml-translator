mod arch;
mod error;
mod litmus;
mod output;
mod parse;

use std::io::Write;
use std::path::{Path, PathBuf};

use clap::{CommandFactory, Parser};
use colored::*;
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
    input: Option<Vec<PathBuf>>,
    #[arg(short, long, help = "output file or dir (default is stdout)")]
    output: Option<PathBuf>,
    #[arg(short, long, help = "allow overwriting files with output")]
    force: bool,
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn process_toml(raw_toml: String) -> error::Result<String> {
    let parsed_litmus = parse::parse(&raw_toml)?;
    output::write_output(parsed_litmus)
}

fn is_toml(p: &Path) -> bool {
    p.extension().filter(|ext| ext.to_str().unwrap() == "toml").is_some()
}

fn process_path(file_or_dir: &Path, out_dir: &Path, force: bool) -> error::Result<()> {
    if file_or_dir.is_dir() {
        let dir = file_or_dir;
        let files = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|entry| entry.is_dir() || is_toml(entry));
        for input in files {
            log::info!("dir:{dir:?} input:{input:?}");
            process_path(&input, &out_dir.join(PathBuf::from(input.file_name().unwrap())), force).unwrap();
        }
    } else {
        let file = file_or_dir;
        if !is_toml(file) {
            log::info!("skipping {file:?}");
            return Ok(());
        }
        let file_name = file.file_name().unwrap().to_string_lossy().into_owned() + ".c";
        let output_path = out_dir.with_file_name(file_name);
        if output_path.exists() && !force {
            log::warn!("file {output_path:?} exists. skipping...");
            eprintln!(
                "{} {} ({} exists)",
                "Skipping".yellow().bold(),
                file.as_os_str().to_string_lossy().bold(),
                output_path.as_os_str().to_string_lossy().bold(),
            );
        } else {
            let toml = std::fs::read_to_string(file).unwrap();
            match process_toml(toml) {
                Ok(output_code) => {
                    let parent = out_dir.parent().unwrap();
                    std::fs::create_dir_all(parent).unwrap();
                    log::info!("creating file at {output_path:?}");
                    let mut f = std::fs::File::create(&output_path).unwrap();
                    log::info!("writing process_toml({file:?}) to {output_path:?}");
                    write!(f, "{output_code}").unwrap();
                    log::info!("successfully translated {file:?} -> {output_path:?}");
                    eprintln!(
                        "{} {} -> {}",
                        "Success".green().bold(),
                        file.as_os_str().to_string_lossy().bold(),
                        output_path.as_os_str().to_string_lossy().bold(),
                    );
                }
                Err(error::Error::Unsupported(e)) => {
                    log::error!("unsupported test {output_path:?} {e}");
                    eprintln!("{} {}", "Unsupported".blue().bold(), file.as_os_str().to_string_lossy().bold(),);
                }
                Err(e) => {
                    log::error!("error translating test {output_path:?} {e}");
                    eprintln!("{} translating {}", "Error".red().bold(), file.as_os_str().to_string_lossy().bold(),);
                }
            }
        }
    }
    Ok(())
}

fn init_logger(verbosity: u8) {
    let filter_level = match verbosity {
        0 => log::LevelFilter::Off,
        1 => log::LevelFilter::Warn,
        2 => log::LevelFilter::Info,
        3 => log::LevelFilter::Debug,
        4.. => log::LevelFilter::Trace,
    };
    pretty_env_logger::formatted_builder().filter_level(filter_level).init();
}

fn main() {
    let cli = Cli::parse();

    init_logger(cli.verbose);

    if let Some(out) = &cli.output {
        if out.exists() && !out.is_dir() && !cli.force {
            log::error!("output file {out:?} exists (and is not a directory). aborting...");
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
                        Err(e) => log::error!("failed to translate toml from stdin {e}"),
                    };
                } else {
                    // let parent = PathBuf::from(path.parent().unwrap());
                    process_path(path, path, cli.force).unwrap();
                }
            } else {
                for path in paths {
                    if let Some(out) = &cli.output {
                        process_path(&path, &out.join(path.file_name().unwrap()), cli.force).unwrap();
                    } else {
                        let parent = PathBuf::from(path.parent().unwrap());
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
                    log::info!("successfully translated stdin -> {out:?}");
                } else {
                    println!("{output_code}");
                }
            }
        }
    }
}
