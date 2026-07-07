#!/bin/bash

set -e
sudo ./build.sh
sudo ./create_cpio.sh
cd ../
./run.sh
cd -
