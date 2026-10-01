use assert_cmd::Command;
use predicates::prelude::*;
use std::fs::File;
use std::io::Write;

#[test]
fn version_flag() {
    Command::cargo_bin("vertex_redact")
        .unwrap()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("0.1.0"));
}

#[test]
fn scan_missing_file_fails() {
    Command::cargo_bin("vertex_redact")
        .unwrap()
        .arg("nonexistent.txt")
        .arg("scan")
        .assert()
        .failure()
        .code(exitcode::DATAERR)
        .stderr(predicate::str::contains("No such file or directory"));
}

#[test]
fn scan_missing_file_extension_success() {
    let dir = assert_fs::TempDir::new().unwrap();
    let file_path = dir.path().join("input_no_ext");
    let mut file = File::create(&file_path).unwrap();
    writeln!(file, "test data").unwrap();
    Command::cargo_bin("vertex_redact")
        .unwrap()
        .arg(file_path)
        .arg("scan")
        .assert()
        .success()
        .stderr(predicate::str::contains("Findings Summary"));
}

#[test]
fn scan_missing_format_success() {
    Command::cargo_bin("vertex_redact")
        .unwrap()
        .write_stdin("hello\nworld\nemail me at h@example.com\n")
        .arg("scan")
        .assert()
        .success()
        .stderr(predicate::str::contains("pii: 1"));
}

#[test]
fn transform_missing_format_success() {
    Command::cargo_bin("vertex_redact")
        .unwrap()
        .write_stdin("hello\nworld\nemail me at h@example.com\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("[REDACTED_EMAIL]"))
        .stderr(predicate::str::contains("pii: 1"));
}

#[test]
fn transform_verbose_success() {
    Command::cargo_bin("vertex_redact")
        .unwrap()
        .write_stdin("hello\nworld\nemail me at h@example.com\n")
        .arg("--verbose")
        .assert()
        .success()
        .stdout(predicate::str::contains("[REDACTED_EMAIL]"))
        .stderr(predicate::str::contains(
            "kind:email\nconfidence:0.90\ndetector:Email\naction:redact_EMAIL\nsource:Stdin\nevidence:\n    - data matched known patterns\n    - surrounding context support",
        ))
        .stderr(predicate::str::contains("pii: 1"));
}
