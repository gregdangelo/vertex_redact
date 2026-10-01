mod common;
use assert_cmd::Command;
use predicates::prelude::*;
use std::fs::File;
use std::io::Write;

#[test]
fn csv_scan_missing_file_extension_success() {
    let dir = assert_fs::TempDir::new().unwrap();
    let file_path = dir.path().join("input_no_ext");
    let mut file = File::create(&file_path).unwrap();
    writeln!(file, "name,city,email\nfake,boston,ex@example.com").unwrap();
    Command::cargo_bin("vertex_redact")
        .unwrap()
        .arg(file_path)
        .arg("scan")
        .assert()
        .success()
        .stderr(predicate::str::contains("Findings Summary"));
}

#[test]
fn csv_scan_missing_format_success() {
    Command::cargo_bin("vertex_redact")
        .unwrap()
        .write_stdin("name,city,email\nfake,boston,ex@example.com\n")
        .arg("scan")
        .assert()
        .success()
        .stderr(predicate::str::contains("pii: 1"));
}

#[test]
fn csv_transform_missing_format_success() {
    Command::cargo_bin("vertex_redact")
        .unwrap()
        .write_stdin("name,city,email\nfake,boston,ex@example.com\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("[REDACTED_EMAIL]"))
        .stderr(predicate::str::contains("pii: 1"));
}

#[test]
fn csv_transform_verbose_success() {
    Command::cargo_bin("vertex_redact")
        .unwrap()
        .write_stdin("name,city,email\nfake,boston,ex@example.com\n")
        .arg("--verbose")
        .arg("-f csv")
        .assert()
        .success()
        .stdout(predicate::str::contains("[REDACTED_EMAIL]"))
        .stderr(predicate::str::contains(
            "kind:email\nconfidence:0.90\ndetector:Email\naction:redact_EMAIL\nsource:Stdin\nevidence:\n    - data matched known patterns\n    - field supports data",
        ))
        .stderr(predicate::str::contains("pii: 1"));
}
