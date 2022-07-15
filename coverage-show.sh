#!/bin/bash
export RUSTFLAGS="-Zinstrument-coverage"
export LLVM_PROFILE_FILE="scratchstack-aws-principal-%m.profraw"
target=target/debug/deps/scratchstack_aws_principal-[a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9]
echo $target
mkdir -p coverage-html
find coverage-html -type f -delete
cargo cov -- show \
    --format=html --ignore-filename-regex='/.cargo/registry' \
    --instr-profile=scratchstack-aws-principal.profdata \
    --object $target \
    --Xdemangler=rustfilt --show-line-counts-or-regions --show-instantiations \
    --output-dir=coverage-html \
    "$@"

case $(uname -s) in
    Darwin )
        open coverage-html/index.html
        ;;
    Linux )
        xdg-open coverage-html/index.html
        ;;
esac
