#!/usr/bin/env sh
## Copyright 2021 Aon plc
## 
## Licensed under the Apache License, Version 2.0 (the "License");
## you may not use this file except in compliance with the License.
## You may obtain a copy of the License at
## 
## http://www.apache.org/licenses/LICENSE-2.0
## 
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.

log() {
    local MESSAGE="${1}"
    local LEVEL="${2:-INFO}"

    echo "::: ${LEVEL}: ${MESSAGE}"
}

print_usage() {
    echo "usage: $(basename ${0}) [-h] SUBCOMMAND"
    echo
    echo "subcommands:"
    echo "black             run Black code formatter"
    echo "make-docs         run Sphinx documentation compiler"
    echo "mypy              run MyPy type checker"
    echo "pylint            run Pylint code linter"
    echo "publish           build distribution packages and publish to PyPI"
    echo "lint              run Pylint code linter and MyPy type checker"
    echo "tests             run unit and documentation tests with Pytest"
    echo
    echo "optional arguments:"
    echo "-h, --help        show this help message and exit"
    echo
}

run_black() {
    log "Running Black code formatter"
    poetry run black "${@}" libcsce/
}

run_make_docs() {
    cd docs && \
        log "Compiling API documentation into RST files" && \
        make apidoc && \
        log "Compiling HTML documentation from RST files" && \
        make html
}

run_mypy() {
    log "Running MyPy type checker"
    poetry run mypy libcsce/
}

run_pylint() {
    log "Running Pylint code linter"
    poetry run pylint --rcfile=pylintrc libcsce/
}

run_publish() {
    log "Building distribution packages" && \
        poetry build && \
        log "Publishing to PyPI" && \
        poetry publish "${@}"
}

run_lint() {
    run_pylint && run_mypy
}

run_tests() {
    log "Running tests with Pytest"
    poetry run pytest --doctest-modules "${@}"
}

if [ $# -lt 1 ]
then
    print_usage
    exit 1
else
    while test $# -gt 0
    do
        case "${1}" in
            -h | --help)
                shift
                print_usage
                shift $#
            ;;
            black)
                shift
                run_black
                shift $#
            ;;
            make-docs)
                shift
                run_make_docs
                shift $#
            ;;
            mypy)
                shift
                run_mypy
                shift $#
            ;;
            pylint)
                shift
                run_pylint
                shift $#
            ;;
            publish)
                shift
                run_publish
                shift $#
            ;;
            lint)
                shift
                run_lint
                shift $#
            ;;
            tests)
                shift
                run_tests
                shift $#
            ;;
            *)
                shift
            ;;
        esac
    done
fi
