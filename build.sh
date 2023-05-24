
#!/bin/bash
make run

if test -d ./build;then
    echo "build dictory exist!"
    rm -rf ./build
fi

mkdir ./build

cd ./build && ../../init-build.sh -DPLATFORM=spike -DSIMULATION=TRUE && ninja
