#!/usr/bin/env bash

set -e

function print_help() {
  echo 'Usage: build.sh [OPTIONS]'
  echo ''
  echo 'Options:'
  echo '  -h,--help         Print this help message and exit'
  echo '  --beta            Build as `-beta` version.'
}

beta=false
while [[ $# -gt 0 ]]; do
  key="$1"
  case $key in
      -h|--help)
        print_help
        exit 0
      ;;
      --beta)
        beta="true"
        shift # past argument
      ;;
      *) # unknown option
        echo 'ERROR: Unknown option'
        echo ''
        print_help
        exit 1
      ;;
  esac
done

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
BASE_NAME=$(jq -r .name pkg/package.json | sed 's/\-/_/g')

PKG_NAME=$(jq -r .name pkg/package.json)
if [[ "$beta" == "true" ]]; then
    PKG_NAME="$PKG_NAME-beta"
fi

# Merge nodejs & browser packages
cp "pkg-node/${BASE_NAME}.js" "pkg/${BASE_NAME}_main.js"
cp "pkg-node/${BASE_NAME}.d.ts" "pkg/${BASE_NAME}_main.d.ts"

sed -i '' "s/__wbindgen_placeholder__/wbg/g" "pkg/${BASE_NAME}_main.js"

PACKAGE_JSON=$(
    jq ".name = \"$PKG_NAME\" | .main = \"${BASE_NAME}_main.js\" | .browser = \"${BASE_NAME}.js\"" \
    pkg/package.json
)
echo "$PACKAGE_JSON" > pkg/package.json

rm -rf pkg-node
