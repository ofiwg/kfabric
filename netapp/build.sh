#!/bin/bash

rm -fv compile.log

make clean

make 2>&1 | tee compile.log

chmod 666 compile.log

sudo make install

make clean
