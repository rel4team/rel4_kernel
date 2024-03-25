#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <num_threads>"
    exit 1
fi

num_threads=$1

for((i=1; i<=$num_threads; i++))
do
    python3 net_test.py &
done

wait

echo "test end" 
