#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
classifier="${repository_root}/scripts/classify-build-units.jq"
expected="$(mktemp)"
observed="$(mktemp)"
trap 'rm -f "${expected}" "${observed}"' EXIT

cat > "${expected}" <<'EOF'
build-helper	1.0.0	build-dependency
build-transitive	1.0.0	build-dependency
direct-helper	1.0.0	proc-macro-dependency
macro-root	1.0.0	proc-macro
transitive-helper	1.0.0	proc-macro-dependency
EOF

jq --raw-output --from-file "${classifier}" <<'JSON' | LC_ALL=C sort > "${observed}"
{
  "packages": [
    {"id":"app","name":"app","version":"1.0.0","targets":[{"kind":["lib"]}]},
    {"id":"macro","name":"macro-root","version":"1.0.0","targets":[{"kind":["proc-macro"]}]},
    {"id":"direct","name":"direct-helper","version":"1.0.0","targets":[{"kind":["lib"]}]},
    {"id":"transitive","name":"transitive-helper","version":"1.0.0","targets":[{"kind":["lib"]}]},
    {"id":"dev-only","name":"dev-only","version":"1.0.0","targets":[{"kind":["lib"]}]},
    {"id":"build","name":"build-helper","version":"1.0.0","targets":[{"kind":["lib"]}]},
    {"id":"build-transitive","name":"build-transitive","version":"1.0.0","targets":[{"kind":["lib"]}]}
  ],
  "resolve": {
    "nodes": [
      {"id":"app","deps":[
        {"pkg":"macro","dep_kinds":[{"kind":null}]},
        {"pkg":"build","dep_kinds":[{"kind":"build"}]}
      ]},
      {"id":"macro","deps":[
        {"pkg":"direct","dep_kinds":[{"kind":null}]},
        {"pkg":"dev-only","dep_kinds":[{"kind":"dev"}]}
      ]},
      {"id":"direct","deps":[{"pkg":"transitive","dep_kinds":[{"kind":null}]}]},
      {"id":"transitive","deps":[]},
      {"id":"dev-only","deps":[]},
      {"id":"build","deps":[{"pkg":"build-transitive","dep_kinds":[{"kind":null}]}]},
      {"id":"build-transitive","deps":[]}
    ]
  }
}
JSON

diff --unified "${expected}" "${observed}"
