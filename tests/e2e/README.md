# Fisherman end-to-end tests

The executable black-box tests live inside the Go module at
`fisherman/tests/e2e`. They build the real CLI, invoke it as a subprocess, and
exercise recipe validation through the command-line boundary without touching
real disks.

Run the suite from the repository root:

```sh
tests/e2e/run.sh
```

Destructive full-install and boot tests use the Bootcrew recipes in the root
`justfile` and require a disposable disk or VM.
