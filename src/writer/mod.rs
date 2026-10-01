use crate::Format;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WriterError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("csv: {0}")]
    Csv(#[from] csv::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriterKind {
    Csv,
    Stdout,
    File,
}
pub trait Writer {
    fn write(&mut self, value: &str) -> Result<(), WriterError>;
    fn end_row(&mut self) -> Result<(), WriterError>;
    fn finish(&mut self) -> Result<(), WriterError>;
    fn write_headers(&mut self, headers: &[String]) -> Result<(), WriterError>;
    #[allow(dead_code)]
    fn kind(&self) -> WriterKind;
}

pub struct StdoutWriter {
    out: BufWriter<io::Stdout>,
}
impl StdoutWriter {
    pub fn new() -> Self {
        Self {
            out: BufWriter::new(io::stdout()),
        }
    }
}
impl Writer for StdoutWriter {
    fn write(&mut self, value: &str) -> Result<(), WriterError> {
        write!(self.out, "{}", value)?;
        Ok(())
    }
    fn end_row(&mut self) -> Result<(), WriterError> {
        writeln!(self.out)?;
        Ok(())
    }
    fn finish(&mut self) -> Result<(), WriterError> {
        self.out.flush()?;
        Ok(())
    }
    fn write_headers(&mut self, headers: &[String]) -> Result<(), WriterError> {
        // this is hardcoded for CSV and I hate it ;)
        writeln!(self.out, "{}", headers.join(","))?;
        Ok(())
    }
    fn kind(&self) -> WriterKind {
        WriterKind::Stdout
    }
}

pub struct FileWriter {
    out: BufWriter<File>,
}
impl FileWriter {
    pub fn new(f: File) -> Self {
        Self {
            out: BufWriter::new(f),
        }
    }
}

impl Writer for FileWriter {
    fn write(&mut self, value: &str) -> Result<(), WriterError> {
        write!(self.out, "{}", value)?;
        Ok(())
    }
    fn end_row(&mut self) -> Result<(), WriterError> {
        writeln!(self.out)?;
        Ok(())
    }
    fn finish(&mut self) -> Result<(), WriterError> {
        self.out.flush()?;
        Ok(())
    }
    fn write_headers(&mut self, headers: &[String]) -> Result<(), WriterError> {
        // this is hardcoded for CSV and I hate it ;)
        writeln!(self.out, "{}", headers.join(","))?;
        Ok(())
    }
    fn kind(&self) -> WriterKind {
        WriterKind::File
    }
}

struct CsvWriter<W: std::io::Write> {
    writer: csv::Writer<W>,
    current_fields: Vec<String>,
}
impl<W: std::io::Write> CsvWriter<W> {
    pub fn new(inner: W) -> Self {
        Self {
            writer: csv::Writer::from_writer(inner),
            current_fields: Vec::new(),
        }
    }
}
impl<W: std::io::Write> Writer for CsvWriter<W> {
    fn write(&mut self, value: &str) -> Result<(), WriterError> {
        self.current_fields.push(value.to_string());
        Ok(())
    }
    fn end_row(&mut self) -> Result<(), WriterError> {
        self.writer.write_record(&self.current_fields)?;
        self.current_fields.clear();
        Ok(())
    }
    fn finish(&mut self) -> Result<(), WriterError> {
        self.writer.flush()?;
        Ok(())
    }
    fn write_headers(&mut self, headers: &[String]) -> Result<(), WriterError> {
        self.writer.write_record(headers)?;
        Ok(()) // actually this is wrong ;) if it is CSV it should write
    }
    fn kind(&self) -> WriterKind {
        WriterKind::Csv
    }
}

// This could be changed to how the reader now is setup with a separate function to determine which writer
pub fn make_writer(
    format: &Format,
    output: Option<PathBuf>,
) -> Result<Box<dyn Writer>, WriterError> {
    match (output, format) {
        (None, f) => {
            // Stdout
            match f {
                Format::Csv => Ok(Box::new(CsvWriter::new(BufWriter::new(io::stdout())))),
                // JSON/L - temporarily
                _ => Ok(Box::new(StdoutWriter::new())),
            }
        }
        (Some(path), f) => {
            let file = File::create(path).map_err(WriterError::Io)?;
            match f {
                Format::Text => Ok(Box::new(FileWriter::new(file))),
                Format::Csv => Ok(Box::new(CsvWriter::new(file))),
                // JSON/L - temporarily
                _ => Ok(Box::new(FileWriter::new(file))), // stdout
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use tempfile::NamedTempFile;

    use super::*;

    fn get_path_buf() -> PathBuf {
        let tmp = NamedTempFile::new().unwrap().into_temp_path();
        tmp.to_path_buf()
    }

    #[test]
    fn test_make_writer() {
        //update test as we get more formats onboard
        let test_data = [
            ("Format:csv, ouput:none", Format::Csv, None, WriterKind::Csv),
            (
                "Format:csv, ouput:file",
                Format::Csv,
                Some(get_path_buf()),
                WriterKind::Csv,
            ),
            (
                "Format:text, ouput:none",
                Format::Text,
                None,
                WriterKind::Stdout,
            ),
            (
                "Format:text, ouput:file",
                Format::Text,
                Some(get_path_buf()),
                WriterKind::File,
            ),
            (
                "Format:jsonl, ouput:none",
                Format::Jsonl,
                None,
                WriterKind::Stdout,
            ),
            (
                "Format:jsonl, ouput:file",
                Format::Jsonl,
                Some(get_path_buf()),
                WriterKind::File,
            ),
            (
                "Format:json, ouput:none",
                Format::Json,
                None,
                WriterKind::Stdout,
            ),
            (
                "Format:json, ouput:file",
                Format::Json,
                Some(get_path_buf()),
                WriterKind::File,
            ),
        ];

        for (n, f, p, k) in test_data {
            let writer = make_writer(&f, p.clone()).unwrap();
            assert_eq!(
                writer.kind(),
                k,
                "name={:?} format={:?}, output={:?}",
                n,
                &f,
                p
            )
        }
    }
}
