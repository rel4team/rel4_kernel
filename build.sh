
#!/bin/bash
cd ..
make run

if test -d ./build;then
    echo "build dictory exist!"
else
    mkdir ./build
fi

cd ./build && ../../init-build.sh -DPLATFORM=spike -DSIMULATION=TRUE && ninja
