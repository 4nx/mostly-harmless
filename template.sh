#!/usr/bin/env bash
# Bash. Copyright (c) 2017, Simon Krenz

# exit if a command fails
set -o errexit
# exit status of last command that threw a non-zero exit code will return
set -o pipefail
# exit if there are undeclared variables
set -o nounset
# tracing and debugging
[[ "${DEBUG}" == 'true' ]] && set -o xtrace

# magic variables
__dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
__file="${__dir}/$(basename "${BASH_SOURCE[0]}")"
__base=="$(basename ${__file} .sh)"

# static variables
declare -r -i int_var=111
declare -r -a my_array=( one two )

arg1="${1:-default}"

# functions
usage() {

}

my_function() {
    local -r var1="${1:-}"; shift
    local -r var2="${1:-}"; shift
    local -r var3=one
}

main () {

}

main "$@"
