# End-to-end tests

These tests exercise the compiled `fisherman` CLI as a subprocess. They cover
the command-line and recipe-loading boundary without performing destructive
disk operations.

Run them from the repository root:

```sh
go test ./tests/e2e
```

Full installation tests require a disposable block device and belong in the
hardware qualification suite rather than the default `go test ./...` run.
