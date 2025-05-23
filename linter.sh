#!/bin/bash

ACTION="check"
EXIT_CODE=0

if [ "$#" -eq 1 ]; then
  if [ "$1" == "format" ]; then
    ACTION="format"
  elif [ "$1" != "check" ]; then
    echo "Invalid argument: $1" >&2
    echo "Usage: $0 [check|format]" >&2
    exit 1
  fi
fi

if [ "$ACTION" == "check" ]; then
  xcrun swift-format lint . \
    --parallel \
    --recursive \
    --strict
  EXIT_CODE=$?
else
  xcrun swift-format format . \
    --parallel \
    --recursive \
    -i
  EXIT_CODE=$?
fi

exit $EXIT_CODE
