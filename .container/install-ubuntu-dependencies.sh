#!/bin/bash

# To make it easier for build and release pipelines to run apt-get,
# configure apt to not require confirmation (assume the -y argument by default)
DEBIAN_FRONTEND=noninteractive

sudo apt-get update && sudo apt-get install -y gnupg wget

#install .NET and T4 text transform
apt install -y dotnet-sdk-8.0
dotnet tool install --global dotnet-t4 --version 2.3.1

sudo apt-get install -y --no-install-recommends \
        curl \
        git \
        build-essential \
        gcc \
        g++ \
        make \
        cmake \
        libelf-dev \
        llvm \
        clang \
        libxml2 \
        libxml2-dev \
        libzstd1 \
        libgtest-dev \
        libc6-dev-i386 \
        apt-transport-https \
        dirmngr \
        googletest \
        google-mock \
        libgmock-dev \
        libjson-glib-dev \
        liblocale-gettext-perl \
        ca-certificates \
        fakeroot \
        lsb-release \
        software-properties-common \
        gettext \
        pax \
        clang-tools \
        libssl-dev

sudo wget https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/openat2.h -O /usr/include/linux/openat2.h

# install debbuild
wget https://github.com/debbuild/debbuild/releases/download/22.02.1/debbuild_22.02.1-0ubuntu20.04_all.deb \
    && sudo dpkg -i debbuild_22.02.1-0ubuntu20.04_all.deb

PATH="$PATH:/root/.dotnet/tools"
