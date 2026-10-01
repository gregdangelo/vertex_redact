/*
    CSV from file is this whol approach but if we're piping the data in that is a different story
*/
use crate::source::{Reader, ReaderError, ReaderKind, Source};
use std::fs::File;
#[allow(unused_imports)]
use std::io::SeekFrom; // not sure why my analyser complains about this file
use std::io::prelude::*;

pub struct CsvReader<R: std::io::Read + std::io::Seek> {
    reader: csv::Reader<R>,
    path: String,
    headers: Vec<String>, // store the header values for context later
    column: usize,
    line: usize,
    record: csv::StringRecord, // the current record
    len: usize,                // number of columns
                               // columns: Vec<usize>, // these are the columns we want to look at currenly unused i.e. 1,3,5 (we only look at these) or -4,-5 (skip these columns)
}
impl CsvReader<File> {
    pub fn from_file(file: File) -> Result<Self, ReaderError> {
        let mut reader = csv::Reader::from_reader(file);
        let headers: Vec<String> = reader
            .headers()?
            .clone()
            .iter()
            .map(|h| h.to_string())
            .collect();
        Ok(Self {
            reader,
            path: String::new(),
            column: 0,
            line: 0,
            record: csv::StringRecord::new(),
            len: headers.len(),
            headers,
        })
    }
}

// #[allow(dead_code)]
impl CsvReader<std::io::Cursor<Vec<u8>>> {
    // TODO: we should be using this
    pub fn from_stdin() -> Result<Self, ReaderError> {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        let mut reader = csv::Reader::from_reader(std::io::Cursor::new(buf));
        let headers: Vec<String> = reader
            .headers()?
            .clone()
            .iter()
            .map(|h| h.to_string())
            .collect();
        Ok(Self {
            reader,
            path: String::new(),
            column: 0,
            line: 0,
            record: csv::StringRecord::new(),
            len: headers.len(),
            headers,
        })
    }
}
impl<R: std::io::Read + std::io::Seek> CsvReader<R> {
    fn move_column(&mut self) -> usize {
        //move to the next column
        if self.column < self.len - 1 {
            self.column += 1
        } else {
            self.column = 0
        }
        self.column
    }
    fn move_row(&mut self) {
        self.line += 1;
    }
    fn next_record(&mut self) -> Result<Option<csv::StringRecord>, ReaderError> {
        match self.reader.records().next() {
            None => Ok(None), // EOF
            Some(Ok(r)) => {
                if r.len() != self.len {
                    return Err(ReaderError::ColumnCount {
                        expected: self.len,
                        found: r.len(),
                    });
                }
                self.move_row();
                Ok(Some(r))
            }
            Some(Err(e)) => Err(ReaderError::Csv(e)),
        }
    }
}
impl<R: std::io::Read + std::io::Seek> Reader for CsvReader<R> {
    // get next cell
    fn next(&mut self) -> Result<Option<String>, ReaderError> {
        // first time get the initial record
        if self.column == 0 && self.line == 0 {
            match self.next_record()? {
                None => return Ok(None), // EOF at first line... empty file
                Some(r) => self.record = r,
            }
        } else if self.move_column() == 0 {
            match self.next_record()? {
                None => return Ok(None), // no more rows
                Some(r) => self.record = r,
            }
        }
        Ok(self.record.get(self.column).map(|s| s.trim().to_string()))
    }

    fn source(&mut self) -> Source {
        Source::Csv {
            path: self.path.clone(),
            line: self.line,
            column: self.column,
        }
    }
    fn field(&self) -> Option<String> {
        eprintln!(
            "field:{} column:{}",
            self.headers.get(self.column).cloned().unwrap(),
            self.column
        );
        self.headers.get(self.column).cloned()
    }
    fn headers(&self) -> Option<&[String]> {
        Some(&self.headers)
    }
    fn kind(&self) -> ReaderKind {
        ReaderKind::Csv
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    /*
       use a basic multi-line file to validate cell walking
    */
    fn get_file() -> File {
        let data = "\
        city,country,popcount
        Boston,United States,4628910
        Bukhorn,Canada,1576
";
        let mut tmpfile = NamedTempFile::new().expect("ths owrks");
        tmpfile.write_all(data.as_bytes()).expect("this also works");
        tmpfile.as_file().seek(SeekFrom::Start(0)).unwrap(); // go back to the beginning
        tmpfile.into_file()
    }

    #[test]
    fn test_file_with_headers() {
        let mut reader = CsvReader::from_file(get_file()).unwrap();
        assert_eq!(3, reader.len);
        assert_eq!("city".to_string(), reader.field().unwrap());
        reader.move_column();
        assert_eq!("country".to_string(), reader.field().unwrap());
        reader.move_column(); // popcount
        reader.move_column(); //back to the beginning
        assert_eq!("city".to_string(), reader.field().unwrap());
    }

    // TODO: fix this test
    #[test]
    fn test_next() {
        let mut reader = CsvReader::from_file(get_file()).unwrap();
        assert_eq!(3, reader.len);

        let expected = [
            ("city", "Boston"),
            ("country", "United States"),
            ("popcount", "4628910"),
            ("city", "Bukhorn"),
            ("country", "Canada"),
            ("popcount", "1576"),
        ];

        // loop through all expected values
        for (expected_field, expected_value) in expected {
            let record = reader
                .next()
                .unwrap_or_else(|_| panic!("expected a record for {}", expected_field));
            assert_eq!(reader.field().unwrap(), expected_field);
            assert_eq!(record.unwrap(), expected_value.to_string());
        }

        // do one more read to find EOF
        assert!(reader.next().unwrap().is_none(), "this should be the end")
    }
}
