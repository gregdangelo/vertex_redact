# clean up
.Phony: try test build clean try-scan policy verify cli cli-json help cli-file cli-verbose cli-csv

try:
	cat pipeme.txt | cargo run 1> pipeme.log 2> pipeme.err.log

try-scan:
	cat pipeme.txt | cargo run scan 1> pipeme.log 2> pipeme.err.log

help:
	./target/debug/vertex_redact --help

cli:
	cat pipeme.txt | ./target/debug/vertex_redact 1> pipeme.log 2> pipeme.err.log

cli-verbose:
	cat pipeme.txt | ./target/debug/vertex_redact --verbose 1> pipeme.log 2> pipeme.err.log

cli-file:
	./target/debug/vertex_redact file_readme.txt 1> pipeme.log 2> pipeme.err.log

cli-csv:
	./target/debug/vertex_redact csv_test.csv 1> pipeme.csv 2> pipeme.err.log

cli-json:
	cat pipeme.txt | ./target/debug/vertex_redact --format json 1> pipeme.log 2> pipeme.err.log

build:
	cargo build

test:
	cargo test

clean:
	cargo clean

# I don't like this one 
policy:
	cargo run init

verify:
	cargo run verify
