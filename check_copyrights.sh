#!/bin/bash
# 
# Copyright 2025 Signal Messenger, LLC
# SPDX-License-Identifier: AGPL-3.0-only

OUT=0
for pattern in '*.rs' '*.proto' '*.sh'; do
  for file in `find ./ -name "$pattern" ! -path './target/*' ! -path './proofs/*' ! -path './.git/*'`; do
    if ! head $file | grep -q Copyright; then
      OUT=1
      echo "Missing copyright in '$file'" 1>&2
    fi
  done
done
exit $OUT
