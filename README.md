# rel4_kernel
This is Rust version of seL4.

## Get Code
```shell
$ mkdir rel4test && cd rel4test
$ repo init -u https://github.com/rel4team/sel4test-manifest.git
$ repo sync
```
## Run seL4test on qemu
please ensure your code version:
- rel4_kernel branch: fpga_test
- seL4test: main
- tools/opensbi branch: v1.3
```shell
# In rel4_kernel dirctory
$ cd rel4_kernel 
$ make env
$ ./build.py
# build smp version
$ ./build.py -c 4

# run on qemu
$ cd build
$ ./simulate -b <your qemu path> -M virt --cpu-num <cpu-num> #(1 or 4)
```

## Run rust demo on qemu
Clone rust-root-task-demo first
```shell
git clone https://github.com/rel4team/rust-root-task-demo.git projects/rust-root-task-demo
```

install header file
```shell
# in rel4_kernel dir
$ ./build.py -c 4 -u -i
```

configure your envionment variables
```shell
vim ~/.bashrc 
export SEL4_INSTALL_DIR=/home/xxx/workspace/rel4test/kernel/install
export SEL4_PREFIX=/home/xxx/workspace/rel4test/kernel/install
```
Build binary image:
```shell
./build.py -c 4 -u -r
```

Run test
```shell
./simulate -b <your qemu path> -M virt --cpu-num 4
```