. as $metadata
| def children($ids):
    [$metadata.resolve.nodes[]
     | select(.id as $id | ($ids | index($id)) != null)
     | .deps[]
     | select(any(.dep_kinds[]; .kind != "dev"))
     | .pkg] | unique;
  def closure($ids):
    (children($ids) - $ids) as $new
    | if ($new | length) == 0
      then $ids
      else closure(($ids + $new) | unique)
      end;
  ([.resolve.nodes[].deps[]
    | select(any(.dep_kinds[]; .kind == "build"))
    | .pkg] | unique | closure(.)) as $build_ids
| ([.packages[]
    | select(any(.targets[]; .kind | index("proc-macro")))
    | .id] | unique) as $proc_macro_roots
| ($proc_macro_roots | closure(.) | . - $proc_macro_roots) as $proc_macro_dependency_ids
| .packages[]
| . as $package
| ([
    if any(.targets[]; .kind | index("custom-build"))
      then "custom-build" else empty end,
    if any(.targets[]; .kind | index("proc-macro"))
      then "proc-macro" else empty end,
    if ($build_ids | index($package.id)) != null
      then "build-dependency" else empty end,
    if ($proc_macro_dependency_ids | index($package.id)) != null
      then "proc-macro-dependency" else empty end
  ] | unique | sort) as $roles
| select($roles | length > 0)
| [$package.name, $package.version, ($roles | join(","))]
| @tsv
