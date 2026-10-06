# go_sigdb

Generates the Go standard-library signature databases in `angr_data/go/sigdb/`
(`go<major.minor>.json`), consumed by `angr.go.signature.GoSignatureSet.from_json`.

The tool type-checks every package of `go list std` (including `internal/...`,
`vendor/...` and `runtime/internal/...`) from source with the toolchain that runs
it, so it must be run once per Go release, with that release's own `go` binary:

```sh
cd tools/go_sigdb
GOROOT=/opt/go1.22.5 GOTOOLCHAIN=local /opt/go1.22.5/bin/go run . -o ../../angr_data/go/sigdb/go1.22.json
GOROOT=/opt/go1.27.1 GOTOOLCHAIN=local /opt/go1.27.1/bin/go run . -o ../../angr_data/go/sigdb/go1.27.json
```

Flags: `-goos` (default `linux`), `-goarch` (default `amd64`; also selects the
sizes/offsets), `-wrappers=false` to drop compiler-generated method wrappers,
`-v` to list type-check errors and assembly-only symbols. Build constraints are
evaluated with `CGO_ENABLED=0`.

## What is emitted

- `functions`: every package-level function and every method (exported and
  unexported, including bodyless assembly-backed declarations), keyed by linker
  symbol name (`strconv.Atoi`, `os.(*File).Write`, `time.Time.Add`,
  `vendor/golang.org/x/net/dns/dnsmessage.(*Parser).Start`). Promoted-method and
  pointer-receiver wrappers the compiler synthesizes (`bufio.(*ReadWriter).Read`,
  `time.(*Time).Add`) are included too. Unnamed or blank parameters are named
  `~p<i>` (index over receiver+params) and unnamed results `~r<i>`, exactly as
  the compiler names them. A variadic parameter is recorded with its slice type.
- `types`: every non-generic named type declared at package level: `struct`
  (fields with byte offsets; embedded fields are named after their type),
  `interface` (flattened, sorted method set) or `named` (with `underlying`), plus
  `size` and `align` for `goarch`.
- Skipped: generic functions/types (only instantiations exist in binaries),
  type aliases (e.g. `runtime._type = internal/abi.Type`), constraint
  interfaces, predeclared types (`error`, `any`), closures and other
  compiler-generated functions, and assembly symbols without a Go declaration.

Type strings are canonical Go syntax with full-import-path-qualified named types
(`*net/http.Server`, `[]byte`, `struct { x int; y int }`, `interface { Error() string }`,
`any`, `sync/atomic.Pointer[runtime.g]`, `func(string, ...any) (int, error)`).
