# Vertex Redact

## Purpose

To remove, redact, psuedomize (sp?) and or mask data from a file or pipe that is sensitive in nature.  Based on rules it removes PII, such as email or credit card or SSN, as well as secrets, like JWT, Authorization or data base connetions, from the data provided. (Work in progress)

Rules determine what to look for, what do do with it once found and transformation instructions if required.

The goal is to transform 2-5 MB worth of data at a time which is a standard log rotation size or a CSV that I would typically be given.  These cover the current needs that I havein my day to day work and I will be exanding on this project as I go.

## Usage

### Setup
Create or overwrite a `policy.toml` file.
```bash
vertex_redact init
```

Verify a `policy.toml` file
```bash
vertex_redact verify
```

Basic policy file contains each rule that can be run.  Disabling rules does affet performance.
```toml
[[rule]]
id = "credit_card"
enabled = true
action = "mask"
confidence = 0.5
keep_last = 4

[[rule]]
id = "email"
enabled = true
action = "redact"
confidence = 0.5
replacement = "EMAIL"

[[rule]]
id = "connection"
enabled = true
action = "report"
confidence = 0.5

[[rule]]
id = "ip"
enabled = true
action = "mask"
confidence = 0.5
keep_last = 1
```

Custom Rules can be added as such
```toml
[[custom_rule]]
id = "employee_id"
enabled = true
pattern = '\bEMP-[0-9]{6}\b'
action = "mask"
keep_first = 3
```
they are the same as standard rules but allow you to add a custom regex `pattern`.  Any item that matches will be considered high enough confidence.  It is best to test out patterns to make sure that they are not being greedy before running against real data

### Scanning

If you just want to analyze a file and not transform it you can simply scan it.  See Analysis section for how that looks

```bash
cat pipeme.txt | vertex_redact scan 1> pipeme.log 2> pipeme.err.log
```

### Transform

Transformed data either goes to `STDOUT` or the given file

Piping from file to a log file
```bash
cat pipeme.txt | vertex_redact 1> pipeme.log 2> pipeme.err.log
```

CSV file - *a header row is assumed*
```bash
vertex_redact csv_test.csv 1> pipeme.csv 2> pipeme.err.log
```

### Analysis
```bash
Vertex Redact 0.1.0
---------- Findings Summary ----------
pii: 2
```
contains version along with counts of each finding kind (PII, Secrets, Custom)

using the `-v` enable verbose analysis which will report on all findings.
```bash
example data goes here :)
```

### Contact
Greg D'Angelo
[LinkedIn](https://linkedin.com/in/gregdangelo)