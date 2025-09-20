#!/bin/bash

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"

PROJECT_FILE="FullStackTests.xcodeproj"
SCHEME="FullStackTests"
DESTINATION="platform=macOS"
TEST_TARGET="FullStackTestsTests"

get_test_classes() {
    if [[ ! -d "Tests" ]]; then
        echo -e "${RED}Error: Tests/ directory not found${NC}" >&2
        return 1
    fi
    rg -A 5 "@Suite" Tests/ | rg "struct\s+(\w+)" -r '$1' --only-matching 2>/dev/null | sort | uniq || true
}

validate_class_name() {
    local class_name="$1"
    if ! get_test_classes | grep -q "^$class_name$"; then
        echo -e "${RED}Error: Class '$class_name' not found${NC}" >&2
        echo -e "${YELLOW}Available classes:${NC}"
        get_test_classes | sed 's/^/  /'
        return 1
    fi
}

list_all_tests() {
    echo -e "${BLUE}Test Suites:${NC}"
    echo

    local classes=()
    while IFS= read -r class; do
        [[ -n "$class" ]] && classes+=("$class")
    done < <(get_test_classes)

    local total_classes=${#classes[@]}
    local class_index=0

    for class in "${classes[@]}"; do
        class_index=$((class_index + 1))
        local is_last_class=$((class_index == total_classes))
        if [[ $is_last_class -eq 1 ]]; then
            echo -e "└── ${CYAN}$class${NC}"
        else
            echo -e "├── ${CYAN}$class${NC}"
        fi
    done
}

list_class_tests() {
    local class_name="$1"

    validate_class_name "$class_name" || return 1

    echo -e "${BLUE}Test Suite: ${CYAN}$class_name${NC}"
    echo
    echo -e "${GREEN}Note: Swift Testing doesn't support individual test method execution with xcodebuild.${NC}"
    echo -e "${GREEN}Use './run-tests.sh --class $class_name' to run all tests in this suite.${NC}"
}

run_test() {
    local test_selection="$1"
    local description="$2"

    set -o pipefail  # Ensure pipeline fails if xcodebuild fails

    echo -e "${GREEN}Running: $description${NC}"
    echo

    if [[ ! -d "$PROJECT_FILE" ]]; then
        echo -e "${RED}Error: Project file $PROJECT_FILE not found${NC}" >&2
        return 1
    fi
    if ! xcodebuild test \
        -project "$PROJECT_FILE" \
        -scheme "$SCHEME" \
        -destination "$DESTINATION" \
        ${test_selection:+$test_selection} 2>&1 | \
        xcbeautify --disable-logging; then
        echo -e "${RED}Test execution failed${NC}" >&2
        return 1
    fi
}

show_usage() {
    echo -e "${BLUE}FullStackTests Runner${NC}"
    echo
    echo -e "${CYAN}Usage:${NC}"
    echo "  $0                               # Interactive mode (default)"
    echo "  $0 --all                         # Run all test suites"
    echo "  $0 --class <class_name>          # Run specific test suite"
    echo "  $0 --list                        # List all test suites"
    echo "  $0 --list-class <class_name>     # Show info for specific suite"
    echo "  $0 --help                        # Show this help message"
    echo
    echo -e "${YELLOW}Note: Individual test method execution is not supported with Swift Testing + xcodebuild.${NC}"
}

interactive_mode() {
    echo -e "${BLUE}Interactive Test Suite Runner${NC}"
    echo -e "${YELLOW}Type to search | Enter: Run | Esc: Quit${NC}"
    echo

    while true; do
        local classes=()
        while IFS= read -r class; do
            [[ -n "$class" ]] && classes+=("$class")
        done < <(get_test_classes)

        if [[ ${#classes[@]} -eq 0 ]]; then
            echo -e "${RED}No test suites found${NC}" >&2
            return 1
        fi

        local selected
        selected=$(printf '%s\n' "${classes[@]}" | fzf \
            --multi \
            --prompt="Select test suite(s): " \
            --height=80% \
            --layout=reverse \
            --border \
            --header="Test Suites | Tab: Multi-select | Enter: Run | Esc: Quit" || true)

        if [[ -z "$selected" ]]; then
            echo -e "${YELLOW}Exiting interactive mode...${NC}"
            break
        fi

        clear

        while IFS= read -r line; do
            if [[ -n "$line" ]]; then
                echo -e "${BLUE}Running: ${CYAN}$line${NC}"
                echo
                if ! run_test "-only-testing:${TEST_TARGET}/$line" "$line"; then
                    echo -e "${RED}Failed to run test suite: $line${NC}" >&2
                fi
                echo
            fi
        done <<< "$selected"

        echo
        echo -e "${GREEN}Press Enter to continue...${NC}"
        read -r || true
        clear
        echo -e "${BLUE}Interactive Test Suite Runner${NC}"
        echo -e "${YELLOW}Type to search | Enter: Run | Esc: Quit${NC}"
        echo
    done
}

main() {
    trap 'echo -e "${RED}\nInterrupted${NC}" >&2; exit 130' INT TERM

    if ! cd "$PROJECT_DIR"; then
        echo -e "${RED}Error: Cannot access project directory $PROJECT_DIR${NC}" >&2
        exit 1
    fi

    if [[ ! -d "$PROJECT_FILE" ]]; then
        echo -e "${RED}Error: $PROJECT_FILE not found in $PROJECT_DIR${NC}" >&2
        exit 1
    fi

    local missing_deps=()

    if ! command -v xcodebuild &> /dev/null; then
        missing_deps+=("xcodebuild (Install Xcode command line tools)")
    fi

    if ! command -v rg &> /dev/null; then
        missing_deps+=("ripgrep (brew install ripgrep)")
    fi

    if ! command -v xcbeautify &> /dev/null; then
        missing_deps+=("xcbeautify (brew install xcbeautify)")
    fi

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        echo -e "${RED}Error: Missing required dependencies:${NC}" >&2
        for dep in "${missing_deps[@]}"; do
            echo -e "  ${YELLOW}• $dep${NC}" >&2
        done
        echo >&2
        echo -e "${CYAN}Install all dependencies and try again.${NC}" >&2
        exit 1
    fi

    local command="${1:-}"
    local class_name="${2:-}"

    if [[ -z "$command" ]]; then
        if ! command -v fzf &> /dev/null; then
            echo -e "${RED}Error: Interactive mode requires fzf${NC}" >&2
            echo -e "${YELLOW}Install with: brew install fzf${NC}" >&2
            echo >&2
            echo -e "${CYAN}Or use one of these options:${NC}" >&2
            show_usage
            exit 1
        fi
        interactive_mode || exit 1
        exit 0
    fi

    case "$command" in
        "--all")
            run_test "" "All Test Suites"
            ;;
        "-h"|"--help"|"help")
            show_usage
            exit 0
            ;;
        "--list")
            list_all_tests
            exit 0
            ;;
        "--list-class")
            if [[ -z "$class_name" ]]; then
                echo -e "${RED}Error: Class name required. Usage: $0 --list-class <class_name>${NC}"
                exit 1
            fi
            list_class_tests "$class_name" || exit 1
            exit 0
            ;;
        "--class")
            if [[ -z "$class_name" ]]; then
                echo -e "${RED}Error: Class name required. Usage: $0 --class <class_name>${NC}"
                exit 1
            fi

            validate_class_name "$class_name" || exit 1

            run_test "-only-testing:${TEST_TARGET}/$class_name" "$class_name" || exit 1
            ;;
        *)
            echo -e "${RED}Error: Unknown option: $command${NC}" >&2
            echo
            show_usage
            exit 1
            ;;
    esac
}

main "$@" || exit $?
