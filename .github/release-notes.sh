#!/usr/bin/env bash
# Prints the notes for release tag $1: the tag message, written by hand in
# Russian, then the commits since the previous tag grouped by type.
set -euo pipefail
tag=$1
prev=$(git describe --tags --abbrev=0 "$tag^" 2>/dev/null || true)
range=${prev:+$prev..}$tag

if [ "$(git cat-file -t "$tag")" = tag ]; then
  git for-each-ref "refs/tags/$tag" --format='%(contents:subject)%0a%0a%(contents:body)'
  echo
fi

section() {
  local lines
  lines=$(git log --no-merges --reverse --format=%s "$range" |
    grep -E "^($2)(\([a-z0-9-]+\))?!?: " |
    sed -E 's/^[a-z]+(\(([a-z0-9-]+)\))?!?: (.*)$/- \3 `\2`/; s/ ``$//' || true)
  if [ -n "$lines" ]; then
    printf '### %s\n\n%s\n\n' "$1" "$lines"
  fi
}
section "Новое" feat
section "Исправления" fix
section "Быстродействие" perf
section "Документация" docs
section "Внутренние изменения" 'refactor|test|ci|build|chore'

if [ -n "$prev" ]; then
  echo "**Все изменения:** https://github.com/${GITHUB_REPOSITORY:-Nettrove/no-mintsifra}/compare/$prev...$tag"
  echo
fi
