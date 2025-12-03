#!/bin/bash

cleanup() {
    rm -rf bin
}

trap cleanup EXIT

mkdir -p bin

REMOTE_USER="$USER"
REMOTE_HOST="10.255.37.136"

# Build server
go build -o ./bin/server ./server

if [ $? -ne 0 ]; then
    echo "Server build failed"
    exit 1
fi

# SCP server to remote host
scp ./bin/server "$REMOTE_USER@$REMOTE_HOST:~"
if [ $? -ne 0 ]; then
    echo "SCP failed"
    exit 1
fi