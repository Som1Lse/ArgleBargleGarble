#!/bin/bash

Url=https://homes.esat.kuleuven.be/~nsmart/MPC

source circuits.sh

if [ ! -d circuits ]; then
    mkdir circuits
fi

for f in "${Files[@]}"; do
    if [ ! -f "circuits/$f.txt" ]; then
        echo "$f"
        curl "$Url/$f.txt" > "circuits/$f.txt"
    fi
done
