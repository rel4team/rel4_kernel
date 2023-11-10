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
$ make env
# build disable smp version
$ ./build.py
# build enable smp version
$ ./build.py -c 4
# build baseline version(c impl)
$ ./build.py -b
```

## How to run test?
```shell
# In build dirctory
$ ./simulate

# In SMP version
$ ./simulate --cpu-num 4
```