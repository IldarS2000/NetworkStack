#!/bin/bash

set -e
set -x

DEPLOY_ROOT=$(dirname "$(realpath "$0")")
cd ${DEPLOY_ROOT}
PROJECT_ROOT=${DEPLOY_ROOT}/..
DEPLOY_TEMP_PATH=${DEPLOY_ROOT}/temp

function deploy_prepare()
{
    rm -rf ${DEPLOY_TEMP_PATH}
    mkdir -p ${DEPLOY_TEMP_PATH}
}

function setup_hugepages()
{
    sysctl -w vm.nr_hugepages=1024

    MOUNT_POINT="/mnt/huge"
    if [ ! mountpoint -q "${MOUNT_POINT}" ]; then
        echo "Mounting hugepages"
        mkdir -p ${MOUNT_POINT}
        mount -t hugetlbfs nodev ${MOUNT_POINT}
    else
        echo "Hugepages are already mounted at ${MOUNT_POINT}"
    fi
}

function copy_artifacts_for_build()
{
    cp -f ${PROJECT_ROOT}/build/output/bin/* ${DEPLOY_TEMP_PATH}
    cp -f ${DEPLOY_ROOT}/Dockerfile ${DEPLOY_TEMP_PATH}
    cp -f ${DEPLOY_ROOT}/fwdd.service ${DEPLOY_TEMP_PATH}
}

function build_docker_image()
{
    docker build -t nstk .
}

function post_clean()
{
    rm -rf ${DEPLOY_TEMP_PATH}
}

deploy_prepare
setup_hugepages
copy_artifacts_for_build
build_docker_image
post_clean