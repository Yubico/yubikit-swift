#!/usr/bin/env bash

assert_success() {
    [[ $status -eq 0 ]] || {
        echo "Command failed with status $status: $output" >&2
        return 1
    }
}

assert_failure() {
    [[ $status -ne 0 ]] || {
        echo "Command should have failed but succeeded: $output" >&2
        return 1
    }
}

assert_output_contains() {
    local expected="$1"
    [[ "$output" =~ $expected ]] || {
        echo "Output does not contain '$expected'. Actual output: $output" >&2
        return 1
    }
}

assert_file_exists() {
    local file="$1"
    [[ -f "$file" ]] || {
        echo "Expected file does not exist: $file" >&2
        return 1
    }
}
