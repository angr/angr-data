// go_sigdb dumps the signatures of every package-level function and method and
// every named type of the Go standard library of the toolchain that runs it,
// in the JSON schema consumed by angr.go.signature.GoSignatureSet.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type listPkg struct {
	ImportPath string
	Name       string
	Dir        string
	GoFiles    []string
	SFiles     []string
	ImportMap  map[string]string
	Error      *struct{ Err string }
}

type funcSig struct {
	Recv    []string    `json:"recv,omitempty"`
	Params  [][2]string `json:"params"`
	Results [][2]string `json:"results"`
}

type sigDB struct {
	GoVersion string                    `json:"go_version"`
	GoArch    string                    `json:"goarch"`
	Functions map[string]*funcSig       `json:"functions"`
	Types     map[string]map[string]any `json:"types"`
}

type gen struct {
	goarch  string
	fset    *token.FileSet
	sizes   types.Sizes
	pkgs    map[string]*listPkg
	order   []string
	files   map[string][]*ast.File
	typed   map[string]*types.Package
	loading map[string]bool
	errs    []string
	db      *sigDB

	nFuncs, nMethods, nWrappers, nTypes int
	nGenericFuncs, nGenericTypes        int
	nConstraintTypes, nAliases          int
}

func main() {
	goBin := flag.String("go", filepath.Join(runtime.GOROOT(), "bin", "go"), "go binary of the toolchain to describe")
	goarch := flag.String("goarch", "amd64", "GOARCH used for build constraints, sizes and offsets")
	goos := flag.String("goos", "linux", "GOOS used for build constraints")
	out := flag.String("o", "", "output JSON path (default: go<major.minor>.json in the current directory)")
	wrappers := flag.Bool("wrappers", true, "also emit promoted-method and pointer-receiver wrappers (pkg.T.M / pkg.(*T).M) the compiler generates")
	verbose := flag.Bool("v", false, "list type-check errors and assembly-only symbols")
	flag.Parse()

	version := goEnv(*goBin, "GOVERSION")
	if version != runtime.Version() {
		fatalf("toolchain %s is %s but this tool was built with %s; run it with the toolchain it describes", *goBin, version, runtime.Version())
	}
	if *out == "" {
		*out = shortVersion(version) + ".json"
	}

	g := &gen{
		goarch:  *goarch,
		fset:    token.NewFileSet(),
		sizes:   types.SizesFor("gc", *goarch),
		pkgs:    map[string]*listPkg{},
		files:   map[string][]*ast.File{},
		typed:   map[string]*types.Package{},
		loading: map[string]bool{},
		db: &sigDB{
			GoVersion: version,
			GoArch:    *goarch,
			Functions: map[string]*funcSig{},
			Types:     map[string]map[string]any{},
		},
	}
	if g.sizes == nil {
		fatalf("unsupported goarch %q", *goarch)
	}
	g.list(*goBin, *goos, *goarch)
	g.parseAll()
	for _, path := range g.order {
		if _, err := g.load(path); err != nil {
			fatalf("%s: %v", path, err)
		}
	}
	for _, path := range g.order {
		if pkg := g.typed[path]; pkg != nil {
			g.dump(pkg, *wrappers)
		}
	}
	asmOnly := g.asmOnly()

	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		fatalf("%v", err)
	}
	f, err := os.Create(*out)
	if err != nil {
		fatalf("%v", err)
	}
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(g.db); err != nil {
		fatalf("%v", err)
	}
	if err := w.Flush(); err != nil {
		fatalf("%v", err)
	}
	f.Close()

	fmt.Fprintf(os.Stderr, "%s %s/%s: %d packages, %d functions (%d funcs, %d methods, %d wrappers), %d types\n",
		version, *goos, *goarch, len(g.typed), len(g.db.Functions), g.nFuncs, g.nMethods, g.nWrappers, len(g.db.Types))
	fmt.Fprintf(os.Stderr, "skipped: %d generic funcs/methods, %d generic types, %d constraint interfaces, %d aliases\n",
		g.nGenericFuncs, g.nGenericTypes, g.nConstraintTypes, g.nAliases)
	fmt.Fprintf(os.Stderr, "%d type-check errors, %d assembly-only symbols without a Go declaration\n", len(g.errs), len(asmOnly))
	if *verbose {
		for _, e := range g.errs {
			fmt.Fprintln(os.Stderr, "  error:", e)
		}
		for _, s := range asmOnly {
			fmt.Fprintln(os.Stderr, "  asm-only:", s)
		}
	}
	fmt.Fprintln(os.Stderr, "wrote", *out)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "go_sigdb: "+format+"\n", args...)
	os.Exit(1)
}

func shortVersion(v string) string {
	parts := strings.Split(strings.TrimPrefix(v, "go"), ".")
	if len(parts) >= 2 {
		return "go" + parts[0] + "." + parts[1]
	}
	return v
}

func goCmd(goBin string, env []string, args ...string) []byte {
	cmd := exec.Command(goBin, args...)
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOFLAGS=", "GOWORK=off")
	cmd.Env = append(cmd.Env, env...)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		fatalf("%s %s: %v", goBin, strings.Join(args, " "), err)
	}
	return out
}

func goEnv(goBin, name string) string {
	return strings.TrimSpace(string(goCmd(goBin, nil, "env", name)))
}

// list runs `go list -json std` under the target GOOS/GOARCH with cgo disabled.
func (g *gen) list(goBin, goos, goarch string) {
	env := []string{"GOOS=" + goos, "GOARCH=" + goarch, "CGO_ENABLED=0"}
	out := goCmd(goBin, env, "list", "-e", "-json=ImportPath,Name,Dir,GoFiles,SFiles,ImportMap,Error", "std")
	dec := json.NewDecoder(bytes.NewReader(out))
	for dec.More() {
		var p listPkg
		if err := dec.Decode(&p); err != nil {
			fatalf("go list: %v", err)
		}
		if p.ImportPath == "unsafe" || len(p.GoFiles) == 0 {
			continue
		}
		if p.Error != nil {
			fmt.Fprintf(os.Stderr, "go list: %s: %s\n", p.ImportPath, p.Error.Err)
		}
		g.pkgs[p.ImportPath] = &p
		g.order = append(g.order, p.ImportPath)
	}
	sort.Strings(g.order)
}

func (g *gen) parseAll() {
	type job struct {
		path string
		i    int
		file string
	}
	var jobs []job
	for _, path := range g.order {
		p := g.pkgs[path]
		g.files[path] = make([]*ast.File, len(p.GoFiles))
		for i, f := range p.GoFiles {
			jobs = append(jobs, job{path, i, filepath.Join(p.Dir, f)})
		}
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	ch := make(chan job)
	for w := 0; w < runtime.NumCPU(); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range ch {
				f, err := parser.ParseFile(g.fset, j.file, nil, parser.SkipObjectResolution)
				if err != nil {
					mu.Lock()
					g.errs = append(g.errs, err.Error())
					mu.Unlock()
				}
				if f != nil {
					g.files[j.path][j.i] = f
				}
			}
		}()
	}
	for _, j := range jobs {
		ch <- j
	}
	close(ch)
	wg.Wait()
}

type importerFunc func(path string) (*types.Package, error)

func (f importerFunc) Import(path string) (*types.Package, error) { return f(path) }

// load type-checks a package (and, on demand, its dependencies) from source.
func (g *gen) load(path string) (*types.Package, error) {
	if path == "unsafe" {
		return types.Unsafe, nil
	}
	if pkg, ok := g.typed[path]; ok {
		return pkg, nil
	}
	if g.loading[path] {
		return nil, fmt.Errorf("import cycle through %s", path)
	}
	lp := g.pkgs[path]
	if lp == nil {
		return nil, fmt.Errorf("package %q is not in `go list std`", path)
	}
	g.loading[path] = true
	defer delete(g.loading, path)

	var files []*ast.File
	for _, f := range g.files[path] {
		if f != nil {
			files = append(files, f)
		}
	}
	conf := types.Config{
		Importer: importerFunc(func(ip string) (*types.Package, error) {
			if m, ok := lp.ImportMap[ip]; ok {
				ip = m
			}
			return g.load(ip)
		}),
		Sizes:            g.sizes,
		IgnoreFuncBodies: true,
		FakeImportC:      true,
		Error: func(err error) {
			g.errs = append(g.errs, err.Error())
		},
	}
	pkg, err := conf.Check(path, g.fset, files, nil)
	if pkg == nil {
		return nil, err
	}
	g.typed[path] = pkg
	return pkg, nil
}

// ---- type strings -------------------------------------------------------

func qualify(pkg *types.Package) string {
	if pkg == nil {
		return ""
	}
	return pkg.Path()
}

func (g *gen) typeString(t types.Type) string {
	var b strings.Builder
	g.writeType(&b, t)
	return b.String()
}

func (g *gen) writeType(b *strings.Builder, t types.Type) {
	t = types.Unalias(t)
	switch t := t.(type) {
	case *types.Basic:
		if t.Kind() == types.UnsafePointer {
			b.WriteString("unsafe.Pointer")
		} else {
			b.WriteString(t.Name())
		}
	case *types.Pointer:
		b.WriteByte('*')
		g.writeType(b, t.Elem())
	case *types.Slice:
		b.WriteString("[]")
		g.writeType(b, t.Elem())
	case *types.Array:
		fmt.Fprintf(b, "[%d]", t.Len())
		g.writeType(b, t.Elem())
	case *types.Map:
		b.WriteString("map[")
		g.writeType(b, t.Key())
		b.WriteByte(']')
		g.writeType(b, t.Elem())
	case *types.Chan:
		parens := false
		switch t.Dir() {
		case types.SendRecv:
			b.WriteString("chan ")
			if c, ok := types.Unalias(t.Elem()).(*types.Chan); ok && c.Dir() == types.RecvOnly {
				parens = true
			}
		case types.SendOnly:
			b.WriteString("chan<- ")
		case types.RecvOnly:
			b.WriteString("<-chan ")
		}
		if parens {
			b.WriteByte('(')
		}
		g.writeType(b, t.Elem())
		if parens {
			b.WriteByte(')')
		}
	case *types.Struct:
		if t.NumFields() == 0 {
			b.WriteString("struct {}")
			return
		}
		b.WriteString("struct { ")
		for i := 0; i < t.NumFields(); i++ {
			if i > 0 {
				b.WriteString("; ")
			}
			f := t.Field(i)
			if !f.Embedded() {
				b.WriteString(f.Name())
				b.WriteByte(' ')
			}
			g.writeType(b, f.Type())
			if tag := t.Tag(i); tag != "" {
				b.WriteByte(' ')
				b.WriteString(strconv.Quote(tag))
			}
		}
		b.WriteString(" }")
	case *types.Interface:
		if t.NumMethods() == 0 && t.NumEmbeddeds() == 0 {
			b.WriteString("any")
			return
		}
		if !t.IsMethodSet() {
			b.WriteString(types.TypeString(t, qualify))
			return
		}
		b.WriteString("interface { ")
		for i := 0; i < t.NumMethods(); i++ {
			if i > 0 {
				b.WriteString("; ")
			}
			m := t.Method(i)
			b.WriteString(m.Name())
			g.writeSignature(b, m.Type().(*types.Signature))
		}
		b.WriteString(" }")
	case *types.Signature:
		b.WriteString("func")
		g.writeSignature(b, t)
	case *types.Named:
		obj := t.Obj()
		if obj.Pkg() != nil {
			b.WriteString(obj.Pkg().Path())
			b.WriteByte('.')
		}
		b.WriteString(obj.Name())
		if args := t.TypeArgs(); args != nil && args.Len() > 0 {
			b.WriteByte('[')
			for i := 0; i < args.Len(); i++ {
				if i > 0 {
					b.WriteByte(',')
				}
				g.writeType(b, args.At(i))
			}
			b.WriteByte(']')
		}
	default:
		b.WriteString(types.TypeString(t, qualify))
	}
}

// writeSignature writes "(params) results" without parameter names.
func (g *gen) writeSignature(b *strings.Builder, sig *types.Signature) {
	b.WriteByte('(')
	params := sig.Params()
	for i := 0; i < params.Len(); i++ {
		if i > 0 {
			b.WriteString(", ")
		}
		pt := params.At(i).Type()
		if sig.Variadic() && i == params.Len()-1 {
			b.WriteString("...")
			pt = types.Unalias(pt).(*types.Slice).Elem()
		}
		g.writeType(b, pt)
	}
	b.WriteByte(')')
	results := sig.Results()
	switch results.Len() {
	case 0:
	case 1:
		b.WriteByte(' ')
		g.writeType(b, results.At(0).Type())
	default:
		b.WriteString(" (")
		for i := 0; i < results.Len(); i++ {
			if i > 0 {
				b.WriteString(", ")
			}
			g.writeType(b, results.At(i).Type())
		}
		b.WriteByte(')')
	}
}

// ---- functions and types ------------------------------------------------

func paramName(name, prefix string, i int) string {
	if name == "" || name == "_" {
		return fmt.Sprintf("%s%d", prefix, i)
	}
	return name
}

// funcSigOf converts a signature; recvName/recvType override the receiver (for wrappers).
func (g *gen) funcSigOf(sig *types.Signature, recvType types.Type) *funcSig {
	fs := &funcSig{Params: [][2]string{}, Results: [][2]string{}}
	idx := 0
	if r := sig.Recv(); r != nil {
		if recvType == nil {
			recvType = r.Type()
		}
		fs.Recv = []string{paramName(r.Name(), "~p", 0), g.typeString(recvType)}
		idx = 1
	}
	params := sig.Params()
	for i := 0; i < params.Len(); i++ {
		p := params.At(i)
		fs.Params = append(fs.Params, [2]string{paramName(p.Name(), "~p", idx), g.typeString(p.Type())})
		idx++
	}
	results := sig.Results()
	for i := 0; i < results.Len(); i++ {
		r := results.At(i)
		fs.Results = append(fs.Results, [2]string{paramName(r.Name(), "~r", i), g.typeString(r.Type())})
	}
	return fs
}

func recvSymbol(pkg *types.Package, recv types.Type) string {
	if p, ok := types.Unalias(recv).(*types.Pointer); ok {
		return pkg.Path() + ".(*" + types.Unalias(p.Elem()).(*types.Named).Obj().Name() + ")"
	}
	return pkg.Path() + "." + types.Unalias(recv).(*types.Named).Obj().Name()
}

func (g *gen) dump(pkg *types.Package, wrappers bool) {
	scope := pkg.Scope()
	for _, name := range scope.Names() {
		switch obj := scope.Lookup(name).(type) {
		case *types.Func:
			sig := obj.Type().(*types.Signature)
			if sig.TypeParams().Len() > 0 {
				g.nGenericFuncs++
				continue
			}
			g.db.Functions[pkg.Path()+"."+name] = g.funcSigOf(sig, nil)
			g.nFuncs++
		case *types.TypeName:
			if obj.IsAlias() {
				g.nAliases++
				continue
			}
			named, ok := obj.Type().(*types.Named)
			if !ok {
				continue
			}
			if named.TypeParams().Len() > 0 {
				g.nGenericTypes++
				g.nGenericFuncs += named.NumMethods()
				continue
			}
			g.dumpType(pkg, named)
			g.dumpMethods(pkg, named, wrappers)
		}
	}
}

func (g *gen) dumpType(pkg *types.Package, named *types.Named) {
	name := pkg.Path() + "." + named.Obj().Name()
	entry := map[string]any{}
	switch u := named.Underlying().(type) {
	case *types.Struct:
		entry["kind"] = "struct"
		var fields []*types.Var
		for i := 0; i < u.NumFields(); i++ {
			fields = append(fields, u.Field(i))
		}
		offsets := g.sizes.Offsetsof(fields)
		list := make([][3]any, len(fields))
		for i, f := range fields {
			list[i] = [3]any{f.Name(), g.typeString(f.Type()), offsets[i]}
		}
		entry["fields"] = list
	case *types.Interface:
		if !u.IsMethodSet() {
			g.nConstraintTypes++
			return
		}
		entry["kind"] = "interface"
		list := make([][2]string, u.NumMethods())
		for i := 0; i < u.NumMethods(); i++ {
			m := u.Method(i)
			var b strings.Builder
			b.WriteString("func")
			g.writeSignature(&b, m.Type().(*types.Signature))
			list[i] = [2]string{m.Name(), b.String()}
		}
		entry["methods"] = list
	default:
		entry["kind"] = "named"
		entry["underlying"] = g.typeString(u)
	}
	entry["size"] = g.sizes.Sizeof(named)
	entry["align"] = g.sizes.Alignof(named)
	g.db.Types[name] = entry
	g.nTypes++
}

func (g *gen) dumpMethods(pkg *types.Package, named *types.Named, wrappers bool) {
	if _, isIface := named.Underlying().(*types.Interface); isIface {
		return
	}
	for i := 0; i < named.NumMethods(); i++ {
		m := named.Method(i)
		sig := m.Type().(*types.Signature)
		g.db.Functions[recvSymbol(pkg, sig.Recv().Type())+"."+m.Name()] = g.funcSigOf(sig, nil)
		g.nMethods++
	}
	if !wrappers {
		return
	}
	for _, recv := range []types.Type{named, types.NewPointer(named)} {
		ms := types.NewMethodSet(recv)
		for i := 0; i < ms.Len(); i++ {
			sel := ms.At(i)
			key := recvSymbol(pkg, recv) + "." + sel.Obj().Name()
			if _, ok := g.db.Functions[key]; ok {
				continue
			}
			g.db.Functions[key] = g.funcSigOf(sel.Obj().Type().(*types.Signature), recv)
			g.nWrappers++
		}
	}
}

// ---- assembly-only symbols ----------------------------------------------

var textRe = regexp.MustCompile(`^TEXT\s+([^\s(,]+)\(SB\)`)

// asmOnly lists TEXT symbols defined in .s files that have no Go declaration.
func (g *gen) asmOnly() []string {
	var out []string
	for _, path := range g.order {
		p := g.pkgs[path]
		for _, sf := range p.SFiles {
			data, err := os.ReadFile(filepath.Join(p.Dir, sf))
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				m := textRe.FindStringSubmatch(line)
				if m == nil || strings.Contains(m[1], "<>") {
					continue
				}
				sym := strings.NewReplacer("·", ".", "∕", "/").Replace(m[1])
				if i := strings.IndexByte(sym, '<'); i >= 0 {
					sym = sym[:i]
				}
				if strings.HasPrefix(sym, ".") {
					sym = path + sym
				}
				if _, ok := g.db.Functions[sym]; !ok {
					out = append(out, sym)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}
