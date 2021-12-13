#!/bin/bash

source circuits.sh

./main.py -p "${Files[@]}" "$@"
