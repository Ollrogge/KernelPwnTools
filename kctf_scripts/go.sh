#!/bin/bash
#
ARG=""
RELEASE=""

case "$1" in
    --lts)
        ARG="LTS=1"
        RELEASE="lts-6.12.46"
        shift
        ;;
    --cos)
        ARG="COS=1"
        RELEASE="cos-121-18867.199.56"
        shift
        ;;
    --mit)
        ARG="MIT=1"
        RELEASE="mitigation-v4-6.6"
        shift
        ;;
esac

echo "Release: $RELEASE"

./build.sh $ARG
if [[ $? -ne 0 ]]; then
    exit 1
fi
sudo --preserve-env=TMUX ./local_runner_customized.sh $RELEASE "$@"

