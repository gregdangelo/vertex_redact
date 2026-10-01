//TODO incorporate this file
/*
Once CSV Reader is finalized and tested this can be worked ok

it contains JSON and JSONL

*/

struct JsonReader { /* holds the parsed Value, yields one "line" per leaf string */ }
// impl Source for JsonReader { /* ... */ }



struct JsonlReader {}
impl JsonlReader {
    pub fn from_file(file: File) -> Result<Self, ReaderError> {
        // ...
        let line: serde_json::Value = serde_json::from_str(s)?;  // serde_json::Error → ReaderError via #[from]
        // ...
    }
    pub fn from_stdin()-> Result<Self, ReaderError> {
        // ...
        let line: serde_json::Value = serde_json::from_str(s)?;  // serde_json::Error → ReaderError via #[from]
        // ...
    }
}