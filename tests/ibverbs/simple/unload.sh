#!/bin/bash

sudo rmmod /lib/modules/`uname -r`/kfabric/kfi_test_simple.ko
sudo rmmod /lib/modules/`uname -r`/kfabric/kfi_verbs.ko
sudo rmmod /lib/modules/`uname -r`/kfabric/kfabric.ko

