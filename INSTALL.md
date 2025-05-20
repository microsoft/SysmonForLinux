# Install Sysmon
Please see the history of this file for instructions for older, unsupported versions.

## Ubuntu
#### 1. Register Microsoft key and feed
```sh
wget -q https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
```

#### 2. Install SysmonForLinux
```sh
sudo apt-get update
sudo apt-get install sysmonforlinux
```

## Debian
#### 1. Register Microsoft key and feed
```sh
wget -q https://packages.microsoft.com/config/debian/$(. /etc/os-release && echo ${VERSION_ID%%.*})/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
```

#### 2. Install SysmonForLinux
```sh
sudo apt-get update
sudo apt-get install apt-transport-https
sudo apt-get update
sudo apt-get install sysmonforlinux
```

## Fedora
#### 1. Register Microsoft key and feed
```sh
sudo rpm -Uvh https://packages.microsoft.com/config/fedora/$(rpm -E %fedora)/packages-microsoft-prod.rpm
```

#### 2. Install SysmonForLinux
```sh
sudo dnf install sysmonforlinux
```

## RHEL
#### 1. Register Microsoft key and feed
```sh
sudo rpm -Uvh https://packages.microsoft.com/config/rhel/$(. /etc/os-release && echo ${VERSION_ID%%.*})/packages-microsoft-prod.rpm
```

#### 2. Install SysmonForLinux
```sh
sudo dnf install sysmonforlinux
```

## openSUSE 15
#### 1. Register Microsoft key and feed
```sh
sudo zypper install libicu
sudo rpm --import https://packages.microsoft.com/keys/microsoft.asc
wget -q https://packages.microsoft.com/config/opensuse/15/prod.repo
sudo mv prod.repo /etc/zypp/repos.d/microsoft-prod.repo
sudo chown root:root /etc/zypp/repos.d/microsoft-prod.repo
```

#### 2. Install SysmonForLinux
```sh
sudo zypper install sysmonforlinux
```

## SLES 15
#### 1. Register Microsoft key and feed
```sh
sudo rpm -Uvh https://packages.microsoft.com/config/sles/15/packages-microsoft-prod.rpm
```

#### 2. Install SysmonForLinux
```sh
sudo zypper install sysmonforlinux
```

