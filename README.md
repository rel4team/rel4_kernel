# rel4_kernel
This is Rust version of seL4.

## How to build & compile?
```shell
# get code
$ mkdir rel4test && cd rel4test
$ repo init -u https://github.com/rel4team/sel4test-manifest.git
$ repo sync

# In rel4_kernel dirctory
$ cd rel4_kernel 
$ make env && ./build.sh
```

## How to run test?
```shell
# In build dirctory
$ ./simulate
```