#!/bin/bash

set -e
set -x

PROJECT_ROOT=$(dirname "$(realpath "$0")")
cd ${PROJECT_ROOT}

function setup_hugepages()
{
    echo "Setup hugepages"
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

function build_docker_image()
{
    echo "Build docker image"
    docker build -t nstk_image .
}

function run_container()
{
    echo "Delete old container"
    docker rm -f nstk || true
    echo "Run container"
    docker run -itd --name nstk --privileged --net=host -v /mnt/huge:/mnt/huge -v /sys/fs/cgroup:/sys/fs/cgroup:ro nstk_image
}

setup_hugepages
build_docker_image
run_container
