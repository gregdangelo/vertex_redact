use anyhow::Result;
// use std::io::{self};
mod analysis;
mod detector;
mod finding;
mod log_processor;
mod pattern;
mod rules;
mod source;
mod validation;
mod writer;
use crate::analysis::Analysis;
use crate::log_processor::RuleProcessor;
// these should end up moving somewhere else
use crate::finding::Finding;
use crate::rules::policy::{init_policy, load_policy};
use crate::source::InputContext;

use crate::source::{Source, make_reader};
use crate::writer::make_writer;
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    // Enable verbose output
    #[arg(short, long)]
    verbose: bool,

    #[arg(default_value_t = "stdin".to_string())]
    input: String,

    #[arg(short, long, default_value_t = "text".to_string())]
    format: String,

    #[arg(short, long)]
    output: Option<PathBuf>,

    // what columns are we looking at OR skipping
    #[arg(short, long, default_value_t = "".to_string())]
    columns: String,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Scan {
        #[arg(default_value_t = "stdin".to_string())]
        input: String,
    },
    Init, // this will be used to generate a policy file containing all the Rules
    Verify,
}

enum Modes {
    Scan,      //  only report
    Transform, // redact/mask etc + report
    Policy,    // generate policy
    Verify,    // verify policy
}
#[derive(Clone, Copy, Debug, PartialEq)]
enum Format {
    Text,
    Json,
    Jsonl,
    Csv,
}

// return this from parse cli args
struct Settings {
    input: source::Source,
    mode: Modes,
    format: Format, //format determines writer
    verbose: bool,
    output: Option<PathBuf>,
}
/*
    only use given format IF we can't tell what kind of file it is.  it is not an override
*/
fn resolve_source_format(input: &str, format: &str) -> (Source, Format) {
    let default_fmt = match format.to_lowercase().as_str() {
        "json" => Format::Json,
        "jsonl" => Format::Jsonl,
        "csv" => Format::Csv,
        _ => Format::Text,
    };
    match input {
        "stdin" => (Source::Stdin { line: 0 }, default_fmt),
        p => {
            let path = PathBuf::from(p);
            match path.extension().and_then(|e| e.to_str()) {
                Some("jsonl") | Some("ndjson") => (
                    Source::Jsonl {
                        path: p.to_string(),
                        line: 0,
                    },
                    Format::Jsonl,
                ),
                Some("json") => (
                    Source::Json {
                        path: p.to_string(),
                        pointer: String::new(),
                    },
                    Format::Json,
                ),
                Some("csv") | Some("tsv") => (
                    Source::Csv {
                        path: p.to_string(),
                        line: 0,
                        column: 0,
                    },
                    Format::Csv,
                ),
                _ => (
                    Source::File {
                        path: p.to_string(),
                        line: 0,
                    },
                    default_fmt,
                ),
            }
        }
    }
}

fn parse_cli_args() -> Settings {
    let cli = Cli::parse();

    let (input, format) = resolve_source_format(cli.input.as_str(), cli.format.as_str());

    let mode: Modes = match &cli.command {
        Some(Commands::Scan { input: _ }) => Modes::Scan,
        Some(Commands::Init) => Modes::Policy,
        Some(Commands::Verify) => Modes::Verify, // this should verify the policy file
        None => Modes::Transform,
    };

    let path = cli.output;

    Settings {
        input: input,
        mode,
        format: format,
        verbose: cli.verbose,
        output: path,
    }
}

fn main() -> Result<()> {
    let version = "0.1.0";
    eprintln!("Vertex Redact {}\n", version);

    let settings: Settings = parse_cli_args(); // → Input
    let mut reader = make_reader(settings.input, &settings.format).unwrap_or_else(|e| {
        eprintln!("Error: {}", e);
        std::process::exit(exitcode::DATAERR);
    }); // → Box<dyn Source>

    let mut writer = make_writer(&settings.format, settings.output).unwrap_or_else(|e| {
        eprintln!("Error: {}", e);
        std::process::exit(exitcode::DATAERR);
    }); // → Box<dyn Source>;

    // this can't be here because if it doesn't exist it fails specifically because I have the exit
    let rules = match load_policy(Path::new("policy.toml")) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(exitcode::CONFIG);
        }
    };

    let mut rules_processor = RuleProcessor::new(rules);

    match settings.mode {
        Modes::Transform => {
            let mut last_line: usize = 0;
            let mut analysis = Analysis::new();

            if let Some(headers) = reader.headers() {
                writer.write_headers(headers)?;
            }

            while let Some(line) = reader.next()? {
                let mut ctx: InputContext = InputContext {
                    text: line,
                    source: reader.source(),
                    field: reader.field(),
                };
                match &ctx.field {
                    None => eprintln!("no field"),
                    Some(f) => eprintln!("field:{}", f),
                };
                let (cleaned, findings) = rules_processor.process(&mut ctx);
                // let a: Analysis = Analysis{findings:findings};
                analysis.findings = findings;
                if settings.verbose {
                    if analysis.findings.len() > 0 {
                        match settings.format {
                            Format::Json => eprintln!("{}", serde_json::to_string(&analysis)?),
                            _ => eprintln!("{}", analysis),
                        }
                    }
                }
                analysis.summarize_findings(); // reset findings

                //check the row
                let current_line = reader.source().line();
                if current_line != last_line {
                    // add this check so that we do NOT add an extra line to the top
                    if last_line != 0 {
                        writer.end_row()?;
                    }
                    last_line = current_line;
                }
                writer.write(&cleaned)?;
            }
            // Don't forget the last row
            writer.end_row()?;
            writer.finish()?;
            analysis.summary()
        }
        Modes::Scan => {
            let mut analysis = Analysis::new();
            while let Some(line) = reader.next()? {
                let mut ctx: InputContext = InputContext {
                    text: line,
                    source: reader.source(),
                    field: reader.field(),
                };
                let findings: Vec<Finding> = rules_processor.scanner(&mut ctx);
                analysis.findings = findings;
                if settings.verbose {
                    if analysis.findings.len() > 0 {
                        match settings.format {
                            Format::Json => eprintln!("{}", serde_json::to_string(&analysis)?),
                            _ => eprintln!("{}", analysis),
                        }
                    }
                }
                analysis.summarize_findings(); // reset findings
            }
            analysis.summary()
        }
        Modes::Policy => init_policy(Path::new("policy.toml")).expect("this better work or else"),
        Modes::Verify => match load_policy(Path::new("policy.toml")) {
            Ok(_) => print!("Policy verified\n"),
            Err(e) => print!("Invalid Policy: {}\n", e),
        },
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::source::Source;

    #[test]
    fn test_resolve_source_formats() {
        let test_data = [
            (
                "file.json",
                "json",
                Source::Json {
                    path: "file.json".to_string(),
                    pointer: String::new(),
                },
                Format::Json,
            ),
            (
                "file.csv",
                "csv",
                Source::Csv {
                    path: "file.csv".to_string(),
                    line: 0,
                    column: 0,
                },
                Format::Csv,
            ),
            ("stdin", "csv", Source::Stdin { line: 0 }, Format::Csv),
        ];
        for (input, format, exp_source, exp_fmt) in test_data {
            let (source, fmt) = resolve_source_format(input, format);
            assert_eq!(source, exp_source, "input:{}, format:{}", input, format);
            assert_eq!(fmt, exp_fmt, "input:{}, format:{}", input, format);
        }
    }
}
/*

On normal JSON: yes, it's worth supporting, and it's not as odd as it seems. The key difference from JSONL:

JSONL — one object per line, you already handle it with your line-based reader. Field paths are shallow (email, user.name).
Normal JSON — a nested document (array of objects, nested objects). You get deep field paths like users[0].credentials.password. That's the whole value — your Candidate already has field_name and container for exactly this.
It's more work (you need serde_json, walk the tree, track a path stack), but it's the format most API responses and structured configs use. I'd do it after JSONL/CSV since it's the most complex of the three.

What else you'll likely need (in rough priority order):

Structured output — right now you're println!-ing. You'll want a --format json mode that emits one JSON object per finding to stdout. This is what makes the tool composable in pipelines (vertex_redact --format json | jq ...).
Exit codes — 0 = clean, 1 = findings detected, 2 = error. Non-negotiable for CI/CD.
Directory scanning — accept a directory path and walk it (filter by extension or --include patterns). Piping a single file is the demo; scanning a repo is the real use case.
Ignore/baseline — a way to suppress known findings (by hash of the finding, or by file+line). Without this, every re-run after a fix still shows the same stale results until you re-baseline.
Progress + timing — for large directories, a simple scanned N files, M findings in Xs summary at the end.
The first three are the "make it usable in CI" tier. The rest are quality-of-life that you'll add when the pain is real.

*/
