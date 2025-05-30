#!/usr/bin/env bash

AVAILABLE_STAGES=("type_check" "code_style_check" "core_unit_tests" "package_install_test"
    "km_tests" "arch_unit_tests" "acceptance_tests"
    "consfuzz_type_check" "consfuzz_style_check" "consfuzz_unit_test")

function parse_args() {
    POSITIONAL_ARGS=()
    IGNORE_ERRORS=false
    STRICT=false
    SKIP_KM_TESTS=false
    STAGE=""

    while [[ $# -gt 0 ]]; do
        case $1 in
        --strict)
            STRICT=true
            shift
            ;;
        --ignore-errors)
            IGNORE_ERRORS=true
            shift
            ;;
        --skip-km-tests)
            SKIP_KM_TESTS=true
            shift
            ;;
        --stage)
            if [ -z "$2" ]; then
                echo "Error: --stage requires an argument"
                exit 1
            fi
            STAGE="$2"
            shift 2
            ;;
        -* | --*)
            echo "Unknown option $1"
            exit 1
            ;;
        esac
    done

    if [[ -n "$STAGE" && ! " ${AVAILABLE_STAGES[@]} " =~ " ${STAGE} " ]]; then
        echo "Invalid stage: $STAGE"
        echo "Available stages: ${AVAILABLE_STAGES[*]}"
        exit 1
    fi

}

# ==================================================================================================
# Testing Stages
# ==================================================================================================
function type_check() {
    local enable_strict=$1

    echo ""
    echo "===== MyPy ====="
    cd $SCRIPT_DIR/.. || exit
    MYPYPATH=rvzr/ python3 -m mypy --strict $ALL_PY --no-warn-unused-ignores --untyped-calls-exclude=elftools
    cd - >/dev/null || exit

    if [ "$enable_strict" = true ]; then
        echo ""
        cd $SCRIPT_DIR/.. || exit
        echo "===== STRICT CHECK: MyPy (Unit Tests) ====="
        MYPYPATH=rvzr/ python3 -m mypy --strict tests/unit_*.py --no-warn-unused-ignores --untyped-calls-exclude=elftools
        MYPYPATH=rvzr/ python3 -m mypy --strict tests/x86_tests/unit_*.py --no-warn-unused-ignores --untyped-calls-exclude=elftools
        MYPYPATH=rvzr/ python3 -m mypy --strict tests/arm64/unit_*.py --no-warn-unused-ignores --untyped-calls-exclude=elftools
        cd - >/dev/null || exit
    fi

}

function code_style_check() {
    local enable_strict=$1

    echo ""
    echo "===== Code Style Checking with flake8 ====="
    cd $SCRIPT_DIR/.. || exit
    python3 -m flake8 --max-line-length 100 --ignore E402,W503 . --count --show-source --statistics
    cd - >/dev/null || exit

    if [ "$enable_strict" = true ]; then
        echo ""
        cd $SCRIPT_DIR/.. || exit
        echo "===== STRICT CHECK: PyLint ====="
        python3 -m pylint --rcfile=.pylintrc $ALL_PY
        cd - >/dev/null || exit
    fi

    echo ""
    echo "===== [DR] Code Style & Linting with clang-tidy ====="
    cd $SCRIPT_DIR/../rvzr/model_dynamorio || exit

    if [ -d "adapter/build" ] || [ -d "backend/build" ]; then
        # this test requires that libstd++-*-dev is installed on the system;
        versions=($(dpkg -l | grep libstdc++- | grep dev | awk '{print $2}' | sed 's/libstdc++-//;s/-dev//'))
        if [ ${#versions[@]} -eq 0 ]; then
            echo "[DR] No libstdc++-*-dev package found; skipping clang-tidy check"
            cd - >/dev/null || exit
            return
        fi

        if [ -d "adapter/build" ]; then
            find . -name "*.c" -or -name "*.h" | grep -v "CMakeFiles" | xargs clang-tidy --quiet -p adapter/build/ --config-file=adapter/.clang-tidy
        fi
        if [ -d "backend/build" ]; then
            find backend -name "*.cpp" -or -name "*.hpp" | grep -v "CMakeFiles" | xargs clang-tidy --quiet --use-color -p backend/build --config-file=backend/.clang-tidy
        fi
    else
        echo "[DR] No build directory for DR backend found; skipping clang-tidy check"
    fi

    cd - >/dev/null || exit
}

function core_unit_tests() {
    echo ""
    echo "===== Core Unit Tests ====="
    cd $SCRIPT_DIR/.. || exit
    python3 -m unittest tests.unit_fuzzer -v
    echo "-------------"
    python3 -m unittest tests.unit_analyser -v
    echo "-------------"
    python3 -m unittest tests.unit_docs -v
    echo "-------------"
    python3 -m unittest tests.unit_isa_loader
    echo "-------------"
    python3 -m unittest tests.unit_stats
    echo "-------------"
    python3 -m unittest tests.unit_tc_components
    echo "-------------"
    python3 -m unittest tests.unit_traces
    cd - >/dev/null || exit
}

function package_install_test() {
    echo ""
    echo "===== Package installation ====="

    # skip if no internet connection
    if ! ping -c 1 8.8.8.8 &>/dev/null; then
        echo "No internet connection, skipping package installation test"
        return
    fi

    cd $SCRIPT_DIR/.. || exit
    python3 -m pip uninstall revizor-fuzzer -y
    python3 -m build
    python3 -m pip install dist/*.whl
    cd - >/dev/null || exit
    cd $SCRIPT_DIR/ || exit
    set +e
    out=$(python3 -c "import rvzr; rvzr.cli.main()" 2>&1)
    set -e
    if [[ "$out" != *"usage: "* ]]; then
        echo "> ERROR: Package installation test failed"
        exit 1
    else
        echo "> Package installation test passed"
    fi
    cd - >/dev/null || exit
}

function km_tests() {
    if [ "$SKIP_KM_TESTS" != true ]; then
        echo ""
        echo "===== Executor kernel module ====="
        cd $SCRIPT_DIR || exit
        ./kernel_module.bats
        cd - >/dev/null || exit
    fi
}

function arch_unit_tests() {
    # Note: we intentionally do not use the 'discover' option because it causes cross-contamination
    # of config options between unit tests

    if [ "$ARCH" == "x86_64" ]; then
        echo ""
        echo "===== x86 unit tests ====="
        cd $SCRIPT_DIR/.. || exit
        python3 -m unittest tests.x86_tests.unit_isa_loader -v
        echo "-------------"
        python3 -m unittest tests.x86_tests.unit_generators -v
        echo "-------------"
        python3 -m unittest tests.x86_tests.unit_model -v
        echo "-------------"
        python3 -m unittest tests.x86_tests.unit_taint_tracker -v
        echo "-------------"
        python3 -m unittest tests.x86_tests.unit_dr_decoder -v
        echo "-------------"
        cd - >/dev/null || exit
        # exit
    else
        echo ""
        echo "===== arm64 unit tests ====="
        cd $SCRIPT_DIR/.. || exit
        cd $SCRIPT_DIR/.. || exit
        python3 -m unittest tests.arm64.unit_isa_loader -v
        echo "-------------"
        python3 -m unittest tests.arm64.unit_generators -v
        echo "-------------"
        # python3 -m unittest tests.arm64.unit_model -v
        # echo "-------------"
        # python3 -m unittest tests.arm64.unit_taint_tracker -v
        # echo "-------------"
        cd - >/dev/null || exit
        # exit
    fi
}

function acceptance_tests() {
    if [ "$SKIP_KM_TESTS" != true ]; then
        echo ""
        echo "===== Acceptance tests ====="
        cd $SCRIPT_DIR || exit
        ./acceptance.bats
        cd - >/dev/null || exit
    fi
}

function consfuzz_type_check() {
    local enable_strict=$1

    echo ""
    echo "===== Consfuzz MyPy ====="
    cd $SCRIPT_DIR/.. || exit
    MYPYPATH=consfuzz/ python3 -m mypy --strict consfuzz/*.py \
        --no-warn-unused-ignores --untyped-calls-exclude=elftools
    cd - >/dev/null || exit

    if [ "$enable_strict" = true ]; then
        echo ""
        cd $SCRIPT_DIR/.. || exit
        echo "===== STRICT CHECK: Consfuzz MyPy (Unit Tests) ====="
        MYPYPATH=consfuzz/ python3 -m mypy --strict tests/consfuzz/unit_*.py \
            --no-warn-unused-ignores --untyped-calls-exclude=elftools
        cd - >/dev/null || exit
    fi
}

function consfuzz_style_check() {
    local enable_strict=$1

    echo ""
    echo "===== Consfuzz style check ====="
    cd $SCRIPT_DIR/.. || exit
    python3 -m flake8 --max-line-length 100 --ignore E402,W503 consfuzz --count --show-source --statistics
    cd - >/dev/null || exit

    if [ "$enable_strict" = true ]; then
        echo ""
        cd $SCRIPT_DIR/.. || exit
        echo "===== STRICT CHECK: Consfuzz PyLint ====="
        python3 -m pylint --rcfile=.pylintrc consfuzz/*.py
        cd - >/dev/null || exit
    fi
}

function consfuzz_unit_test() {
    echo ""
    echo "===== Consfuzz unit tests ====="
    cd $SCRIPT_DIR/.. || exit
    python3 -m unittest tests.consfuzz.unit_config -v
    cd - >/dev/null || exit
}

# ==================================================================================================
# Runners
# ==================================================================================================
function run_one_stage() {
    local stage=$1

    case $stage in
    type_check)
        type_check $STRICT
        ;;
    code_style_check)
        code_style_check $STRICT
        ;;
    core_unit_tests)
        core_unit_tests
        ;;
    package_install_test)
        package_install_test
        ;;
    km_tests)
        km_tests
        ;;
    arch_unit_tests)
        arch_unit_tests
        ;;
    acceptance_tests)
        acceptance_tests
        ;;
    consfuzz_type_check)
        consfuzz_type_check $STRICT
        ;;
    consfuzz_style_check)
        consfuzz_style_check $STRICT
        ;;
    consfuzz_unit_test)
        consfuzz_unit_test
        ;;
    *)
        echo "Unknown stage: $stage"
        exit 1
        ;;
    esac
}

function main() {
    parse_args $@

    if [ "$IGNORE_ERRORS" != "true" ]; then
        set -e
    fi

    if [ "$STRICT" = true ]; then
        echo "Including optional tests"
    fi

    VENDOR="$(lscpu | grep Vendor | awk '{print $3}')"
    ARCH="$(lscpu | grep Architecture | awk '{print $2}')"

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
    ALL_PY=$(find rvzr/ -name "*.py" | grep -v "config" | grep -v "fuzzer")

    # if STAGE is set, run only that stage
    if [[ -n "$STAGE" ]]; then
        run_one_stage "$STAGE"
        exit 0
    fi

    type_check $STRICT
    code_style_check $STRICT
    package_install_test
    core_unit_tests
    km_tests
    arch_unit_tests
    acceptance_tests

    consfuzz_type_check $STRICT
    consfuzz_style_check $STRICT
    consfuzz_unit_test
}

main $@
