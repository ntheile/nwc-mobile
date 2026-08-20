#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
approved="${repository_root}/supply-chain/approved-build-units.txt"
observed="$(mktemp)"
trap 'rm -f "${observed}"' EXIT

cd "${repository_root}"
cargo metadata --locked --format-version 1 \
  | jq --raw-output '
      . as $metadata
      | def children($ids):
          [$metadata.resolve.nodes[]
           | select(.id as $id | ($ids | index($id)) != null)
           | .deps[].pkg] | unique;
        def closure($ids):
          (children($ids) - $ids) as $new
          | if ($new | length) == 0
            then $ids
            else closure(($ids + $new) | unique)
            end;
        ([.resolve.nodes[].deps[]
          | select(any(.dep_kinds[]; .kind == "build"))
          | .pkg] | unique | closure(.)) as $build_ids
      | .packages[]
      | . as $package
      | ([
          if any(.targets[]; .kind | index("custom-build"))
            then "custom-build" else empty end,
          if any(.targets[]; .kind | index("proc-macro"))
            then "proc-macro" else empty end,
          if ($build_ids | index($package.id)) != null
            then "build-dependency" else empty end
        ] | unique | sort) as $roles
      | select($roles | length > 0)
      | [$package.name, $package.version, ($roles | join(","))]
      | @tsv
    ' \
  | LC_ALL=C sort > "${observed}"

if ! diff --unified "${approved}" "${observed}"; then
  printf '%s\n' \
    'Compile-time dependencies changed.' \
    'Review the new crate source, owner, release age, and compile-time code.' \
    'Update supply-chain/approved-build-units.txt only after that review.' >&2
  exit 1
fi
