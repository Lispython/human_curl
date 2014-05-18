#!/bin/sh

REQ_FILE=./req.txt


if [ ! -d "./tools/buildenv.sh" ]; then
	mkdir -p ./tools
	curl -L https://raw.github.com/Lispython/buildenv.sh/master/buildenv.sh > tools/buildenv.sh
fi

. ./tools/buildenv.sh
