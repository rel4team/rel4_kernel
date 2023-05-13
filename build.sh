#!/bin/bash
make run

if test -d ./build;then
    echo "build dictory exist!"
    rm -rf ./build
    mkdir ./build
else
    mkdir ./build
fi

cd ./build && ../../init-build.sh -DPLATFORM=spike -DSIMULATION=TRUE && ninja
