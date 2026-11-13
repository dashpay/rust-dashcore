# dash-spv-bench recipes, run as `just dash-spv-bench::<recipe>`

import "../mod.just"

# Run scenarios (files or globs, relative to where `just` was invoked)
[no-cd]
[positional-arguments]
[unix]
run *args:
    {{ quote(source_directory() / "run.sh") }} "$@"

# Run scenarios (files or globs, relative to where `just` was invoked)
[windows]
run *args:
    {{ error(unix_only) }}

# Run every scenario its `repeats:` times and write a median report
[positional-arguments]
[unix]
scenarios *args:
    ./bench-scenarios.sh "$@"

# Run every scenario its `repeats:` times and write a median report
[windows]
scenarios *args:
    {{ error(unix_only) }}
