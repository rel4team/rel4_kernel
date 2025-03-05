# reL4test RISCV-V下编译环境搭建

Rel4环境配置和源码部署帮助文档

## 背景工具

### Terminal

在本项目中优于PowerShell的终端软件，在Microsoft商店中搜索下载即可。

### Ubuntu

本项目采用Ubuntu 22.04.3 LTS，在Microsoft商店中搜索下载即可用于WSL。

### WSL

- 优势：可以直接访问主机的软硬件资源，不容易出现网络问题
- 使用方法：默认开启，安装Ubuntu后在Terminal中打开Ubuntu即可
- 补充：
  - WSL迁移到非系统盘（WSL默认安装在C盘，可能导致空间不足问题）：[教程](https://blog.csdn.net/m0_37605642/article/details/127812965)
  - 修改root密码（在后续使用中可能会遇到root默认密码未知的问题）：[教程](https://baijiahao.baidu.com/s?id=1751797503085666267&wfr=spider&for=pc)

### 网络

为终端配置网络（每次新开终端都需要配置）

配置步骤：

1. Windows下在cmd输入ipconfig
2. 查看WLAN下IPV4地址，如10.62.58.178
3. 在Ubuntu下输入（需要将127.0.0.1替换为上述IPV4地址）：

```bash
export http_proxy=http://127.0.0.1:7890
export https_proxy=$http_proxy
```

测试方法：在Ubuntu下输入如下代码可以获取对应http内容

```bash
curl -I www.google.com
```

### VSCode编辑器

- 安装方法：在Windows下安装VSCode并配置WSL组件
- 环境配置
  1. 在Ubuntu下安装Rust(安装选项选择default)
  2. 在VSCode安装rust-analyzer组件
- Rust安装Shell指令

```bash
curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh
```

## SeL4运行环境配置

- 按照 [Host Dependencies | seL4 docs](https://docs.sel4.systems/projects/buildsystem/host-dependencies.html#python-dependencies) 安装相应依赖（内容如下）
- 依赖内容
  - Repo
  - Base Dependencies下所有内容
  - Python Dependencies下所有内容
- Tips：如果在安装过程中缺失前置依赖，则安装对应依赖即可

## Qemu模拟器

#### 安装依赖

```bash
sudo apt-get install zlib1g-dev libpixman-1-dev libfdt-dev
```

#### 克隆仓库

```bash
git clone https://github.com/rel4team/qemu.git
```

#### 配置

```bash
./configure --target-list=riscv64-softmmu --disable-werror --prefix=/home/xxx/rel4_qemu/
```

#### 安装

```bash
make -j4
make install
```

## 交叉编译工具

- 基本安装方法

按照 [Host Dependencies | seL4 docs](https://docs.sel4.systems/projects/buildsystem/host-dependencies.html#python-dependencies) 安装“Cross-compiling for RISC-V targets”部分

潜在问题：在make linux时出现Building GCC requires GMP 4.2+, MPFR 3.1.0+ and MPC 0.8.0+问题（暂时无法解决，安装上述以来后仍然报错）

#### 安装依赖

```bash
sudo apt-get install autoconf automake autotools-dev curl python3 python3-pip python3-tomli libmpc-dev libmpfr-dev libgmp-dev gawk build-essential bison flex texinfo gperf libtool patchutils bc zlib1g-dev libexpat-dev ninja-build git cmake libglib2.0-dev libslirp-dev
```

#### 克隆仓库

```HTMLbash
git clone https://github.com/riscv/riscv-gnu-toolchain
```

#### 安装编译

`--prefix` 为编译后的目标路径，`--enable-multilib` 选项用于启用多库支持

make linux选择交叉编译

```HTMLbash
./configure --prefix=/opt/riscv --enable-multilib
make linux -j4
```

编译完成后将--prefix的地址添加到$PATH变量中

- 备选方法（适用于上述方法无法跑通）

在Ubuntu下载解压已经完成编译的工具后，在/bin目录下输入

```bash
./riscv64-unknown-linux-gnu-gcc -v
```

将/bin目录加入环境变量（写入~/.bashrc）

```bash
export PATH="文件位置/bin:$PATH"
```

输入如下内容同步环境变量

```bash
source ~/.bashrc
```

## Rel4运行环境配置

### 基本配置

#### **克隆仓库**

```bash
mkdir rel4test && cd rel4test
repo init -u https://github.com/rel4team/sel4test-manifest.git
repo sync
```

#### **配置环境**

```bash
cd ./rel4_kernel
make env
```

### 构建build.py参数命令解释

- -b：编译c侧接口
- -u：开启用户态中断功能
- -c：开启cpu多核支持，可以输入数字表示cpu核数
- -i：表示install，安装部分头文件内容，生成可执行二进制文件

### C侧代码运行

#### **构建编译：**

进入rel4test/rel4_kernel输入命令

```bash
./build.py -c 4 -u
```

#### **仿真运行：**

进入rel4test/rel4_kernel/build输入如下命令

```bash
./simulate -b qemu-build路径/qemu-system-riscv64 -M virt --cpu-num 4
```

其中：

- -b：指定qemu路径，后续qemu路径需根据以往的qemu配置更改
- -M：指定虚拟机器类型
- --cpu-num：指定cpu核心数量

### Rust侧代码运行

#### **克隆仓库**

在rel4test/projects下递归克隆仓库

```bash
git clone --recurse-submodules https://github.com/rel4team/rust-root-task-demo.git
```

#### **头文件安装**

编译部分C侧头文件供Rust侧内核调用，进入rel4test/rel4_kernel输入命令

```bash
./build.py -c 4 -u -i
```

#### **获取安装路径**

进入rel4test/kernel/install目录输入pwd（获得路径例如）

```bash
/home/xxx/workspace/rel4test/kernel/install
```

#### **配置环境变量**

将路径写入~/.bashrc

```bash
export SEL4_INSTALL_DIR=/home/xxx/workspace/rel4test/kernel/install
export SEL4_PREFIX=/home/xxx/workspace/rel4test/kernel/install
```

#### **同步环境变量**

输入如下命令同步

```bash
source ~/.bashrc
```

#### **验证**

输入命令后可以确认已将路径加入环境变量

```bash
env
```

#### **编译**

在rel4test/rel4_kernel下输入

```bash
./build.py -c 4 -u -r
```

#### **运行**

进入rel4test/rel4_kernel/build输入如下命令

```bash
./simulate -b qemu-build路径/qemu-system-riscv64 -M virt --cpu-num 4
```

### 代码修改后重新编译问题

- 修改用户态代码：重新编译运行即可
- 修改内核态：删除build目录下kernel，重新编译运行即可

### 网络问题

部分环境换国内源方法如下

#### repo

若repo命令报错`	fatal: Cannot get https://gerrit.googlesource.com/git-repo/clone.bundle`,在命令后使用添加选项

`--repo-url=https://gerrit-googlesource.lug.ustc.edu.cn/git-repo`,则该命令使用清华源

#### rust

~/.bashrc

```bash
# 中科大
export RUSTUP_DIST_SERVER=https://mirrors.ustc.edu.cn/rust-static
export RUSTUP_UPDATE_ROOT=https://mirrors.ustc.edu.cn/rust-static/rustup
# 字节
export RUSTUP_DIST_SERVER=https://rsproxy.cn
export RUSTUP_UPDATE_ROOT=https://rsproxy.cn/rustup
```

#### cargo

```bash
[source.crates-io]
replace-with = 'rsproxy'
 
# 清华大学 5mb
[source.tuna]
registry = "https://mirrors.tuna.tsinghua.edu.cn/git/crates.io-index.git"
 
# 中国科学技术大学 2mb
[source.ustc]
registry = "https://mirrors.ustc.edu.cn/crates.io-index"
# 上海交通大学 2mb
[source.sjtu]
registry = "https://mirrors.sjtug.sjtu.edu.cn/git/crates.io-index"
 
# rustcc社区 2mb
[source.rustcc]
registry = "https://crates.rustcc.cn/crates.io-index"
# 字节跳动 10mb
[source.rsproxy]
registry = "https://rsproxy.cn/crates.io-index"

```

测试指令 `cargo check`

## 其他问题（不断更新中）

- Permission Denied：不断尝试或使用chmod指令获取更多权限
- rust版本问题报错:重新make env

```bash
Caused by:61.03package `home va.5.11` cannot be built because it requires rustc 1.81 or newer, while the currently active rustc version is 1.77.0-nightly61.03Either upgrade to rustc 1.81 or newer, or use61.03cargo update home@0.5.11 --precise ver61.03where`ver`is the latest version of `home`supporting rustc 1.77.0-nightly
```

- sel4test编译报错：check sel4test分支到2b63c9183a7aae707004afdbd3157b41aeb3ae7e
- riscv gcc 无法链接浮点数模块：使用本地编译开启--enable-multilib选项的编译器
- 测试运行卡在Initializing PLIC...：使用本地编译的qemu
- r侧代码cmake _cargo-build_example失败：用户态测试代码编译失败，可先单独编译用户态代码查找问题。