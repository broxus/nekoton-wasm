#!/usr/bin/env bash

set -e

# Check if jq is installed
if ! [ -x "$(command -v jq)" ]; then
    echo "jq is not installed" >& 2
    exit 1
fi

# Clean previous packages
if [ -d "pkg" ]; then
    rm -rf pkg
fi

if [ -d "pkg-node" ]; then
    rm -rf pkg-node
fi

# Build for node target
wasm-pack build --release -t nodejs -d pkg

# Get the package name
PKG_NAME=$(jq -r .name pkg/package.json | sed 's/\-/_/g')

sed -i "s/__wbindgen_placeholder__/wbg/g" "pkg/${PKG_NAME}.js"

jq ".main = \"${PKG_NAME}.js\"" pkg/package.json > pkg/temp.json
mv pkg/temp.json pkg/package.json

