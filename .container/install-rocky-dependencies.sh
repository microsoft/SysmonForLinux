#!/bin/bash

# install all needed packges to build .rpm packages
echo "assumeyes=1" >> sudo /etc/yum.conf

# install endpoint for git > 2.0
sudo yum install http://opensource.wandisco.com/rhel/8/git/x86_64/wandisco-git-release-8-1.noarch.rpm

# Enable powertools and extra repos
sudo dnf install dnf-plugins-core && sudo dnf install epel-release && sudo dnf config-manager --set-enabled powertools && sudo dnf update

sudo yum install \
       git \
       gcc \
       gcc-c++ \
       make \
       cmake \
       llvm \
       clang \
       elfutils-libelf-devel \
       rpm-build \
       json-glib-devel \
       python3 \
       glibc-devel.i686 \
       gtest-devel \
       gmock \
       gmock-devel \
       which \
       wget \
       redhat-lsb \
       clang-analyzer \
       openssl-devel

# Remove old pip and setuptools versions due to security issues
sudo pip3 uninstall -y setuptools
sudo pip3 uninstall -y pip

# install JQ since it doesn't have a .rpm package
curl https://stedolan.github.io/jq/download/linux64/jq > sudo /usr/bin/jq && sudo chmod +x /usr/bin/jq

#install .NET and T4 text transform
sudo dnf install dotnet-sdk-6.0
dotnet tool install --global dotnet-t4 --version 2.3.1