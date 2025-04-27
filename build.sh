#!/bin/bash

set -e
set -x

PROJECT_ROOT=$(dirname "$(realpath "$0")")
cd ${PPROJECT_ROOT}
BUILD_DIR=${PROJECT_ROOT}/build

function clean()
{
    rm -rf ${BUILD_DIR}
}

function build()
{
    mkdir -p ${BUILD_DIR}

    pushd ${BUILD_DIR}
        cmake ${PROJECT_ROOT}
        make
    popd
}

clean
build