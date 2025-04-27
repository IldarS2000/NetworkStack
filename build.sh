#! /bin/bash

set -e
set -x

PROJECT_ROOT=$(dirname "$(realpath "$0")")
cd ${PPROJECT_ROOT}
BUILD_DIR=${PROJECT_ROOT}/build

function build_clean()
{
    rm -rf ${BUILD_DIR}
}

function main()
{
    mkdir -p ${BUILD_DIR}

    pushd ${BUILD_DIR}
        cmake ${PROJECT_ROOT}
        make
    popd
}

build_clean
main