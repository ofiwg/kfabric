#!/bin/bash

source ./config.sh

sudo insmod /lib/modules/`uname -r`/kfabric/kfabric.ko
sudo insmod /lib/modules/`uname -r`/kfabric/kfi_verbs.ko
sudo insmod /lib/modules/`uname -r`/kfabric/kfi_test_simple.ko role=server addr=$ADDR port=$PORT
