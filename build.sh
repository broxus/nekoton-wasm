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

# Build for both targets
wasm-pack build --release -t nodejs -d pkg-node
wasm-pack build --release -t web -d pkg

# Get the package name
PKG_NAME=$(jq -r .name pkg/package.json | sed 's/\-/_/g')

# Merge nodejs & browser packages
cp "pkg-node/${PKG_NAME}.js" "pkg/${PKG_NAME}_main.js"
cp "pkg-node/${PKG_NAME}.d.ts" "pkg/${PKG_NAME}_main.d.ts"

sed -i "s/__wbindgen_placeholder__/wbg/g" "pkg/${PKG_NAME}_main.js"

jq ".main = \"${PKG_NAME}_main.js\"" pkg/package.json |
  jq ".browser = \"${PKG_NAME}.js\"" > pkg/temp.json
mv pkg/temp.json pkg/package.json

rm -rf pkg-node
