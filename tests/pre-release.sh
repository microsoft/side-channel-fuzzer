#!/usr/bin/env bash
# FILE: tests/pre-release.sh
#       Run all available demos to ensure that regressions on all known vulnerabilities on
#       the CPU under test

set -o errexit -o pipefail -o noclobber -o nounset
trap exit INT

SCRIPT=$(realpath $0)
SCRIPT_DIR=$(dirname $SCRIPT)

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
reset='\033[0m'

verbose=0
work_dir=""
revizor_dir=${revizor_dir:-"$SCRIPT_DIR/.."}

# ==================================================================================================
# Command-line argument parsing
# ==================================================================================================
function print_help() {
    echo "Usage: $0 [-v] -w <work_dir>"
    echo ""
    echo "Options:"
    echo "  -v, --verbose        Enable verbose output"
    echo "  -w, --workdir        Working directory for temporary files"
}

function read_args() {
    # check for availability of getopt
    getopt --test >/dev/null && true
    if [[ $? -ne 4 ]]; then
        echo 'ERROR: getopt is not available'
        exit 1
    fi

    # List arguments
    LONGOPTS=workdir:,verbose
    OPTIONS=w:v

    # Parse output
    PARSED=$(getopt --options=$OPTIONS --longoptions=$LONGOPTS --name "$0" -- "$@") || exit 2
    eval set -- "$PARSED"

    while true; do
        case "$1" in
        -v | --verbose)
            verbose=0
            ;;
        -w | --workdir)
            work_dir=$2
            shift
            ;;
        --)
            shift
            break
            ;;
        esac
        shift
    done

    # check usage
    if [ -z "$work_dir" ]; then
        print_help
        exit 1
    fi

    # make sure that the directories and required files exist
    if [ ! -d "$work_dir" ]; then
        echo "ERROR: Could not find '$work_dir'"
    fi
    if [ ! -f "$revizor_dir/revizor.py" ]; then
        echo "ERROR: Could not find '$revizor_dir/revizor.py'"
    fi
    if [ ! -f "$revizor_dir/base.json" ]; then
        echo "ERROR: Could not find '$revizor_dir/base.json'"
    fi

    # Globals
    work_dir=$(realpath $work_dir)
    revizor="$revizor_dir/revizor.py"
    instructions="$revizor_dir/base.json"
    conf_dir="$revizor_dir/demo/"

}

# ==================================================================================================
# Patching and manipulation of configuration files
# ==================================================================================================

# array of patches to the configuration file that makes a repro config into a verification config
# the array is a map from the name of the vulnerability to the patch function
declare -A verif_patches
verif_patches["detect-v1"]="contract_execution_clause:\n  - cond"
verif_patches["detect-v1-store"]="contract_observation_clause: ct"
verif_patches["detect-v4"]="x86_executor_enable_ssbp_patch: true"

function make_verification_conf() {
    # create a version of the reproduce file that should NOT trigger a violation if
    # the violation has an expected root cause. E.g., for Spectre V1, we change the contract
    # execution clause to COND instead of SEQ, which means that violations caused by conditional
    # branches should no longer be reported by the fuzzer (i.e., become non-reproducible).

    local name=$1
    local repro_conf=$2
    local verif_conf=$3

    cp $repro_conf $verif_conf
    if [[ ! -v verif_patches[$name] ]]; then
        printf "${yellow}NO VERIFICATION PATCH AVAILABLE${reset}\n"
        return 1
    fi
    local patch=${verif_patches[$name]}
    echo -e "$patch" >>$verif_conf
    return 0
}

function disable_stat_logging() {
    local config=$1

    # disable statistics logging to avoid polluting the output
    echo "logging_modes:" >>$config
    echo "  - info" >>$config
}


function disable_all_logging() {
    local config=$1

    # disable all logging to avoid polluting the output
    echo "logging_modes: []" >>$config
}

# ==================================================================================================
# Functions
# ==================================================================================================
function prep_files_for_run() {
    local name=$1

    # remove leftovers from previous runs
    rm -rf $work_dir &>/dev/null || true
    mkdir -p $work_dir

    # check that the configuration file exists
    org_config="$conf_dir/${name}.yaml"
    if [ ! -f "$org_config" ]; then
        # templated demos have a different naming scheme
        org_config="$conf_dir/$name/config.yaml"
        if [ ! -f "$org_config" ]; then
            echo "ERROR: Could not find '$org_config'"
            exit 1
        fi
    fi

    # make a copy of the configuration file and patch it
    config="$work_dir/conf.yaml"
    cp $org_config $config
    disable_stat_logging $config

    # create a log file
    log="$work_dir/${name}-log.txt"
    rm $log &>/dev/null || true
}

function check_results() {
    # Check the output of the experiment for errors and parse the results

    # arguments
    local log=$1
    local exit_code=$2
    local expected=$3

    # output messages
    fail="${red}FAIL${reset}"
    error="${red}ERROR${reset}"
    ok="${green}PASSED${reset}"

    # check for errors
    if grep "ERROR" $log &>/dev/null; then
        printf "$error\n"
        return 1
    fi
    if grep "Error" $log &>/dev/null; then
        printf "$error\n"
        return 1
    fi
    if grep "Errno" $log &>/dev/null; then
        printf "$error\n"
        return 1
    fi

    # if no violations were found, the test failed
    if [ $exit_code -ne $expected ]; then
        printf "$fail [exit code %s != %s]\n" "$exit_code" "$expected"
        return 1
    fi

    # parse the output
    duration=$(awk '/Duration/{print $2}' $log)
    printf "$ok [%s sec]\n" "$duration"
    return 0
}


function run() {
    local name=$1
    local templated=${2:-0}

    prep_files_for_run $name

    # Print the header
    echo ""
    printf "${yellow}============================= $name =============================${reset}\n"

    # run the test
    printf "${green}+ Detect ...  ${reset}\n"
    set +e
    if [ $verbose -eq 1 ]; then set -x; fi
    if [ $templated -eq 0 ]; then
        python ${revizor} fuzz -s $instructions -c $config -I $conf_dir -i $NUM_INPUTS -n $NUM_PROGS --timeout $TIMEOUT -w "$work_dir" 2>&1 | tee "$log"
    else
        template="$conf_dir/$name/template.asm"
        python ${revizor} tfuzz -s $instructions -t $template -c $config -I $conf_dir -i $NUM_INPUTS -n $NUM_PROGS --timeout $TIMEOUT -w "$work_dir" 2>&1 | tee "$log"
    fi
    exit_code=$?
    if [ $verbose -eq 1 ]; then set +x; fi
    check_results $log $exit_code 1
    if [ $? -ne 0 ]; then return 0; fi
    set -e

    # move the violation into a dedicated dir
    vdir="$work_dir/violation*"
    if [ -d "$vdir" ]; then
        echo "ERROR: Could not find a violation directory: '$vdir'"
        exit 1
    fi

    # reproduce the violations
    printf "${green}+ Reproduce ...  ${reset}\n"
    repro_conf="$vdir/reproduce.yaml"
    disable_all_logging $repro_conf
    set +e
    if [ $verbose -eq 1 ]; then set -x; fi
    python ${revizor} reproduce -s $instructions -c $repro_conf -I $conf_dir -t $vdir/program.asm -i $(ls $vdir/input*.bin) 2>&1 | tee "$log"
    exit_code=$?
    if [ $verbose -eq 1 ]; then set +x; fi
    check_results $log $exit_code 1
    if [ $? -ne 0 ]; then return 0; fi
    set -e

    # verify that the violation has the expected root cause
    printf "${green}+ Verify ...  ${reset}\n"
    verif_conf="$work_dir/verif.yaml"
    set +e
    make_verification_conf $name $repro_conf $verif_conf
    if [ $? -ne 0 ]; then return 0; fi
    if [ $verbose -eq 1 ]; then set -x; fi
    python ${revizor} reproduce -s $instructions -c $verif_conf -I $conf_dir -t $vdir/program.asm -i $(ls $vdir/input*.bin) 2>&1 | tee "$log"
    exit_code=$?
    if [ $verbose -eq 1 ]; then set +x; fi
    check_results $log $exit_code 0
    if [ $? -ne 0 ]; then return 0; fi
    set -e
}

# ==================================================================================================
# Test configuration
NUM_INPUTS=25
NUM_PROGS=1000000000 # some large number that is never reached before the timeout
TIMEOUT=$((10 * 60 * 60))         # seconds

read_args "$@"

# Measurements
printf "Starting at $(date '+%H:%M:%S on %d.%m.%Y')\n"

run "detect-v1"
run "detect-v1-store"
run "detect-v4"

if grep -q 'E-2288G' /proc/cpuinfo; then
    run "detect-mds"
    run "detect-foreshadow"
    run "detect-zdi"
fi

if grep -q 'AMD' /proc/cpuinfo; then
    run "tsa-sq" 1
    run "tsa-l1d" 1
fi

# these two are slow to detect, thus run them last
run "detect-sco"
run "detect-v1-var"
