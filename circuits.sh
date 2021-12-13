#!/bin/bash

export Files=(
    # adder64
    # sub64
    # neg64 # Contains an EQW gate, which the parser doesn't support.
    # mult64
    # mult2_64
    # divide64
    # udivide64
    # zero_equal

    # aes_128
    # aes_192
    # aes_256
    # Keccak_f
    sha256
    sha512

    # FP-add
    # FP-mul
    FP-div
    # FP-eq
    # FP-lt
    # FP-f2i
    # FP-i2f
    FP-sqrt
    # FP-floor
    # FP-ceil
)

# Old circuit. See https://homes.esat.kuleuven.be/~nsmart/MPC/old-circuits.html
export OldFiles=(
    AES-non-expanded
    AES-expanded
    DES-non-expanded
    DES-expanded

    md5
    sha-1
    sha-256

    adder_32bit
    adder_64bit
    mult_32x32
    comparator_32bit_signed_lteq
    comparator_32bit_signed_lt
    comparator_32bit_unsigned_lteq
    comparator_32bit_unsigned_lt
)
