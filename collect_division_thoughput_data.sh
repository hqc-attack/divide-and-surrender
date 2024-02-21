#!/usr/bin/env bash

cd nanoBench
make user
path=/sys/devices/system/cpu/smt/control
previous=$(cat $path)
__cleanup ()
{
    echo $previous > $path
}

trap __cleanup EXIT
echo off > $path

vendor=$(lscpu | grep AMD -q && echo -n "amd" || echo -n "intel")
for ((i=0;i<=32;++i))
    do echo -n "$i",
    ./nanoBench.sh \
        -config ../nanoBench_configs/$vendor.txt \
        -n_measurements 10000 \
        -asm "mov r10, 17669; mov rax, $(python3 -c "print((1<<$i)-1 if $i != 0 else 0)"); xor rdx, rdx; div r10" | grep -Po '\d+\.\d+'
done