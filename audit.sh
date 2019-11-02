#!/usr/bin/env bash
# Bash. Copyright (c) 2017, Simon Krenz
DEBUG=1

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
declare -r -i indent_status=-75
declare -r -i int_var=111
declare -r -a my_array=( one two )

arg1="${1:-default}"

# functions
#usage() {
#}

system_information() {
    echo "------------ SYSTEM INFORMATION -----------------"
    echo -n "OS: " && $(cat /etc/centos-release)
    echo -n "Kernel: " && $(uname -a)
    echo -n "Hostname: " && $(hostname)
}

output_green () {
    local -r text="${1:-}"; shift
    local -r green=$'\e[1;32m'
    local -r end=$'\e[0m'
    printf "${green}%s${end}\n" "${text}"
}

output_red () {
    local -r text="${1:-}"; shift
    local -r red=$'\e[1;31m'
    local -r end=$'\e[0m'
    printf "${red}%s${end}\n" "${text}"
}

section_one() {
    echo "--------------- SECTION ONE ---------------------"
    printf "%s\n" "1.1 Filesystem Configuration"
    printf "%s\n" "1.1.1 Disable unused filesystems"
    printf "%${indent_status}s" "1.1.1.1 Ensure mounting of cramfs filesystems is disabled (Scored)"
    if [[ $(lsmod | grep -c cramfs) ]]; then
        output_green "[ OK ]"
    else
        output_red "[ FAIL ]"
    fi
}

my_function() {
    local -r var1="${1:-}"; shift
    local -r var2="${1:-}"; shift
    local -r var3=one
}

main () {
    printf "%s\n" "CIS Audit Script :: CentOS 7"
    printf "%s: %(%Y/%m/%d %H:%M)T\n" "Date"
    printf "%s\n" "================================================="
    section_one
}

main "$@"
