pub mod csv_reader;
use serde::Serialize;
use std::fs::File;
use std::io::{BufRead, BufReader};
use strum_macros::Display;
use thiserror::Error;

use crate::Format;
use crate::source::csv_reader::CsvReader;

#[derive(Debug, Display, Clone, PartialEq, Serialize)]
pub enum Source {
    Stdin {
        line: usize,
    },
    File {
        path: String,
        line: usize,
    },
    Jsonl {
        path: String,
        line: usize,
    },
    Json {
        path: String,
        pointer: String,
    }, // e.g. "/users/0/email"
    Csv {
        path: String,
        line: usize,
        column: usize,
    },
}

impl Source {
    pub fn path(&self) -> Option<&str> {
        match self {
            Source::File { path, .. }
            | Source::Csv { path, .. }
            | Source::Json { path, .. }
            | Source::Jsonl { path, .. } => Some(path),
            Source::Stdin { .. } => None,
        }
    }
    pub fn line(&self) -> usize {
        match self {
            Source::File { line, .. }
            | Source::Csv { line, .. }
            | Source::Jsonl { line, .. }
            | Source::Stdin { line } => *line,
            Self::Json { .. } => 0,
        }
    }
}

#[allow(dead_code)]
pub struct InputContext {
    pub text: String,
    pub source: Source,
    pub field: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Display, PartialEq)]
pub enum ReaderKind {
    Stdin,
    File,
    Json,
    Csv,
}

#[allow(dead_code)]
pub trait Reader {
    fn next(&mut self) -> Result<Option<String>, ReaderError>;
    fn field(&self) -> Option<String>; // Stdin+File would return none, CSV the header, JSON/L the parent object or key?
    fn source(&mut self) -> Source;
    fn headers(&self) -> Option<&[String]>;
    fn kind(&self) -> ReaderKind;
}

fn read_line_inner(reader: &mut impl BufRead) -> Option<String> {
    let mut buf = String::new();
    let n = reader.read_line(&mut buf).ok()?;
    buf.truncate(n);
    let trimmed = buf.trim_end().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

// --- Concrete implementations ---
struct FileReader {
    reader: BufReader<File>,
    path: String,
    line: usize,
}
impl FileReader {
    fn new(file: File) -> Self {
        Self {
            reader: BufReader::new(file),
            path: "path".to_string(),
            line: 0,
        }
    }
}
impl Reader for FileReader {
    fn next(&mut self) -> Result<Option<String>, ReaderError> {
        self.line += 1;
        Ok(read_line_inner(&mut self.reader))
    }
    fn source(&mut self) -> Source {
        Source::File {
            path: self.path.clone(),
            line: self.line,
        }
    }
    fn field(&self) -> Option<String> {
        None
    }
    fn headers(&self) -> Option<&[String]> {
        None
    }
    fn kind(&self) -> ReaderKind {
        ReaderKind::File
    }
}

struct StdinReader {
    reader: BufReader<std::io::Stdin>,
    line: usize,
}
impl StdinReader {
    fn new() -> Self {
        Self {
            reader: BufReader::new(std::io::stdin()),
            line: 0,
        }
    }
}

impl Reader for StdinReader {
    fn next(&mut self) -> Result<Option<String>, ReaderError> {
        self.line += 1;
        Ok(read_line_inner(&mut self.reader))
    }
    fn source(&mut self) -> Source {
        Source::Stdin { line: self.line }
    }
    fn field(&self) -> Option<String> {
        None
    }
    fn headers(&self) -> Option<&[String]> {
        None
    }
    fn kind(&self) -> ReaderKind {
        ReaderKind::Stdin
    }
}
#[derive(Debug, Display, PartialEq)]
enum ReaderChoice {
    Stdin,
    File,
    CsvFile,
    CsvStdin,
    JsonlFile,
    JsonlStdin,
    JsonFile,
    JsonStdin,
}

#[derive(Debug, Error)]
pub enum ReaderError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("csv: {0}")]
    Csv(#[from] csv::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    // Add your own domain errors as needed:
    #[error("expected {expected} columns, found {found}")]
    ColumnCount { expected: usize, found: usize },

    #[error("Uknown source")]
    SourceUnknown,
}

// determine what reader we will be loading in.
fn reader_choice(input: Source, format: &Format) -> Result<ReaderChoice, ReaderError> {
    match (input, format) {
        (Source::File { .. }, _) => Ok(ReaderChoice::File),
        (Source::Stdin { .. }, format) => match format {
            Format::Csv => Ok(ReaderChoice::CsvStdin),
            Format::Jsonl => Ok(ReaderChoice::JsonlStdin),
            Format::Json => Ok(ReaderChoice::JsonStdin),
            _ => Ok(ReaderChoice::Stdin),
        },
        (Source::Jsonl { .. }, _) => Ok(ReaderChoice::JsonlFile),
        (Source::Json { .. }, _) => Ok(ReaderChoice::JsonFile),
        (Source::Csv { .. }, _) => Ok(ReaderChoice::CsvFile),
    }
}

pub fn make_reader(input: Source, format: &Format) -> Result<Box<dyn Reader>, ReaderError> {
    // read the path and try and open it to fail fast
    let file = input.path().map(std::fs::File::open).transpose()?;
    let rc = reader_choice(input, format)?;
    match (rc, file) {
        (ReaderChoice::File, Some(file)) => Ok(Box::new(FileReader::new(file))),
        (ReaderChoice::Stdin, _) => Ok(Box::new(StdinReader::new())),
        (ReaderChoice::CsvStdin, _) => Ok(Box::new(CsvReader::from_stdin()?)),
        (ReaderChoice::CsvFile, Some(file)) => Ok(Box::new(CsvReader::from_file(file)?)),
        (ReaderChoice::JsonlStdin, Some(..)) => todo!(),
        (ReaderChoice::JsonStdin, Some(..)) => todo!(),
        (ReaderChoice::JsonlFile, Some(..)) => todo!(),
        (ReaderChoice::JsonFile, Some(..)) => todo!(),
        _ => Err(ReaderError::SourceUnknown),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_make_reader() {
        let test_data = [
            (
                "Input:stdin, Format:csv",
                Source::Stdin { line: 0 },
                Format::Csv,
                ReaderChoice::CsvStdin,
            ),
            (
                "Input:csv, Format:csv",
                Source::Csv {
                    path: String::new(),
                    line: 0,
                    column: 0,
                },
                Format::Csv,
                ReaderChoice::CsvFile,
            ),
        ];

        for (n, mut src, fmt, k) in test_data {
            let file = NamedTempFile::new().unwrap();
            let path = file.path().to_str().unwrap().to_string();
            let s = match &mut src {
                Source::Csv { .. } => Source::Csv {
                    path: path,
                    line: 0,
                    column: 0,
                },
                Source::File { .. } | Source::Json { .. } | Source::Jsonl { .. } => src,
                _ => src,
            };
            let reader = reader_choice(s.clone(), &fmt).unwrap_or_else(|e| {
                panic!(
                    "make_reader failed for name={:?} src={:?} fmt={:?}: {e}",
                    n, s, fmt
                )
            });
            assert_eq!(reader, k, "name={:?} input={:?}, format={:?}", n, s, &fmt,);
        }
    }
}
