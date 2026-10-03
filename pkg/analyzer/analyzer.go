package analyzer

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/devenock/specyl/pkg/config"
	"github.com/devenock/specyl/pkg/models"
)

// Analyzer analyzes the codebase to extract API information
type Analyzer struct {
	config            *config.Config
	framework         models.FrameWorkType
	endpoints         []models.Endpoint
	models            map[string]models.Schema
	typeRegistry      map[string]models.Schema
	typePackageName   map[string]string
	stringConsts      map[string]string
	curGroupPrefix    map[string]string
	curAuthGroups     map[string]bool
	curFilePath       string
	consumedCalls     map[*ast.CallExpr]bool
	parseDiagnostics  []ParseDiagnostic
	authMatches       []string
	bindHintMatches   []string
	detectedPort      string
	resolvedLocalPort string

	root *os.Root
}

func (a *Analyzer) walkProjectDir(fn func(fullPath string, d fs.DirEntry) error) error {
	return fs.WalkDir(a.root.FS(), ".", func(relPath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		return fn(filepath.Join(a.config.ProjectPath, relPath), d)
	})
}

func (a *Analyzer) rootReadFile(fullPath string) ([]byte, error) {
	rel, err := filepath.Rel(a.config.ProjectPath, fullPath)
	if err != nil {
		return nil, err
	}
	info, err := a.root.Lstat(rel)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, os.ErrNotExist
	}
	return a.root.ReadFile(rel)
}

func (a *Analyzer) rootParseFile(fset *token.FileSet, fullPath string, mode parser.Mode) (*ast.File, error) {
	data, err := a.rootReadFile(fullPath)
	if err != nil {
		return nil, err
	}
	return parser.ParseFile(fset, fullPath, data, mode)
}

func readProjectFile(projectPath, name string) ([]byte, error) {
	root, err := os.OpenRoot(projectPath)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, os.ErrNotExist
	}
	return root.ReadFile(name)
}

func (a *Analyzer) BindHintMatches() []string {
	return a.bindHintMatches
}

// recordBindHintMatch appends text to bindHintMatches, deduplicated.
func (a *Analyzer) recordBindHintMatch(text string) {
	for _, seen := range a.bindHintMatches {
		if seen == text {
			return
		}
	}
	a.bindHintMatches = append(a.bindHintMatches, text)
}

func (a *Analyzer) AuthMiddlewareMatches() []string {
	return a.authMatches
}

type ParseDiagnostic struct {
	File string
	Err  error
}

func (a *Analyzer) Diagnostics() []ParseDiagnostic {
	return a.parseDiagnostics
}

func (a *Analyzer) recordParseFailure(filePath string, err error) {
	for _, d := range a.parseDiagnostics {
		if d.File == filePath {
			return
		}
	}
	a.parseDiagnostics = append(a.parseDiagnostics, ParseDiagnostic{File: filePath, Err: err})
}

// NewAnalyzer creates a new Analyzer
func NewAnalyzer(cfg *config.Config) *Analyzer {
	return &Analyzer{
		config:       cfg,
		framework:    models.FrameWorkUnknown,
		endpoints:    []models.Endpoint{},
		models:       make(map[string]models.Schema),
		typeRegistry: make(map[string]models.Schema),
	}
}

func (a *Analyzer) Framework() string {
	return string(a.framework)
}

func (a *Analyzer) DetectedPort() string {
	if len(a.config.Servers) > 0 {
		return ""
	}
	return a.resolvedLocalPort
}

// Analyze scans the codebase and extracts API information
func (a *Analyzer) Analyze() (*models.APISpec, error) {
	root, err := os.OpenRoot(a.config.ProjectPath)
	if err != nil {
		return nil, fmt.Errorf("open project directory: %w", err)
	}
	a.root = root
	defer a.root.Close()

	// Detect framework if not specified
	if a.config.Framework == "" {
		if err := a.detectFramework(); err != nil {
			return nil, err
		}
	} else {
		a.framework = models.FrameWorkType(a.config.Framework)
	}

	if a.config.Verbose {
		fmt.Printf("   Detected framework: %s\n", a.framework)
	}

	// Pass 1: collect type definitions from all .go files for request/response schema resolution
	err = a.walkProjectDir(func(path string, d fs.DirEntry) error {
		if d.IsDir() {
			for _, exclude := range a.config.Exclude {
				if filepath.Base(path) == exclude {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		return a.collectTypesInFile(path)
	})
	if err != nil {
		return nil, err
	}

	a.resolveEmbeddedFields()

	// Pass 2: extract routes and resolve handler request/response from type registry
	err = a.walkProjectDir(func(path string, d fs.DirEntry) error {
		if d.IsDir() {
			for _, exclude := range a.config.Exclude {
				if filepath.Base(path) == exclude {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		return a.parseFile(path)
	})
	if err != nil {
		return nil, err
	}

	// Ensure every endpoint has a tag from path (for Swagger grouping by module)
	for i := range a.endpoints {
		if len(a.endpoints[i].Tags) == 0 {
			if t := tagFromPath(a.endpoints[i].Path); t != "" {
				a.endpoints[i].Tags = []string{t}
			}
		}
		// Description fallback: humanize summary when it looks like a handler name (CamelCase) and description is empty
		if a.endpoints[i].Description == "" && a.endpoints[i].Summary != "" {
			if looksLikeHandlerName(a.endpoints[i].Summary) {
				a.endpoints[i].Description = humanizeHandlerName(a.endpoints[i].Summary)
				a.endpoints[i].Summary = humanizeHandlerName(a.endpoints[i].Summary)
			}
		}
	}

	a.resolveHandlerSourceFiles()

	a.resolveRemainingRequestBodies()

	// Same fallback pass for responses (review §3).
	a.resolveRemainingResponses()

	for i := range a.endpoints {
		if len(a.endpoints[i].Responses) == 0 {
			a.endpoints[i].Responses[200] = models.Response{
				Description: "Response shape could not be inferred",
				Content: map[string]models.Content{
					"application/json": {Schema: models.Schema{Type: "object"}},
				},
			}
		}
	}

	// Deduplicate by (method, path), keeping first occurrence
	a.endpoints = a.deduplicateEndpoints(a.endpoints)

	// Filter by --tags, if set. Must run after tags are fully assigned above.
	a.endpoints = a.filterEndpointsByTags(a.endpoints)

	a.addModelsReferencedByEndpoints()

	// Create API spec
	spec := &models.APISpec{
		Title:           a.config.Title,
		Version:         a.config.Version,
		Description:     a.config.Description,
		BasePath:        a.config.BasePath,
		Endpoints:       a.endpoints,
		Models:          a.models,
		TypePackageName: a.typePackageName,
	}

	// Add servers if configured
	if len(a.config.Servers) > 0 {
		for _, srv := range a.config.Servers {
			spec.Servers = append(spec.Servers, models.Server{
				URL:         srv.URL,
				Description: srv.Description,
			})
		}
	} else {

		url := detectServerURL(a.config.ProjectPath)
		if a.detectedPort != "" {
			url = "http://localhost:" + a.detectedPort
		}
		if idx := strings.LastIndex(url, ":"); idx >= 0 {
			a.resolvedLocalPort = url[idx+1:]
		}
		spec.Servers = []models.Server{
			{
				URL:         url,
				Description: "Development server",
			},
		}
	}

	if len(a.parseDiagnostics) > 0 && !a.config.Quiet {
		fmt.Fprintf(os.Stderr, "⚠️  %d file(s) could not be parsed (use -v for detail)\n", len(a.parseDiagnostics))
		if a.config.Verbose {
			for _, d := range a.parseDiagnostics {
				fmt.Fprintf(os.Stderr, "   %s: %v\n", d.File, d.Err)
			}
		}
	}

	if a.config.Verbose && !a.config.Quiet {
		if len(a.authMatches) > 0 {
			fmt.Fprintf(os.Stderr, "   Matched as auth middleware: %s\n", strings.Join(a.authMatches, ", "))
		}
		if len(a.bindHintMatches) > 0 {
			fmt.Fprintf(os.Stderr, "   Matched as request-body binding by name hint: %s\n", strings.Join(a.bindHintMatches, ", "))
		}
	}

	return spec, nil
}

func detectServerURL(projectPath string) string {
	data, err := readProjectFile(projectPath, ".env")
	if err != nil {
		return "http://localhost:8080"
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		for _, key := range []string{"PORT=", "APP_PORT=", "SERVER_PORT=", "HTTP_PORT="} {
			if strings.HasPrefix(line, key) {
				port := strings.Trim(strings.TrimPrefix(line, key), `"' `)
				if port != "" {
					return "http://localhost:" + port
				}
			}
		}
	}
	return "http://localhost:8080"
}

func (a *Analyzer) detectListenPort(n ast.Node) {
	if a.detectedPort != "" {
		return
	}
	call, ok := n.(*ast.CallExpr)
	if !ok || len(call.Args) == 0 {
		return
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return
	}
	var addrArg ast.Expr
	switch sel.Sel.Name {
	case "Run", "Listen", "Start":
		addrArg = call.Args[0]
	case "ListenAndServe":

		if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "http" {
			addrArg = call.Args[0]
		}
	}
	if addrArg == nil {
		return
	}
	addr, ok := a.literalStringArg(addrArg)
	if !ok {
		return
	}
	if port := portFromAddr(addr); port != "" {
		a.detectedPort = port
	}
}

func portFromAddr(addr string) string {
	idx := strings.LastIndex(addr, ":")
	if idx == -1 {
		return ""
	}
	port := addr[idx+1:]
	if port == "" {
		return ""
	}
	for _, r := range port {
		if r < '0' || r > '9' {
			return ""
		}
	}
	return port
}

var frameworkMarkers = []struct {
	framework string
	marker    string
}{
	{string(models.FrameWorkGin), "github.com/gin-gonic/gin"},
	{string(models.FrameWorkEcho), "github.com/labstack/echo"},
	{string(models.FrameWorkFiber), "github.com/gofiber/fiber"},
	{string(models.FrameWorkGorilla), "github.com/gorilla/mux"},
	{string(models.FrameWorkChi), "github.com/go-chi/chi"},
}

func DetectFrameworks(projectPath string) []string {
	content, err := readProjectFile(projectPath, "go.mod")
	if err != nil {
		return nil
	}
	var found []string
	for _, fm := range frameworkMarkers {
		for _, line := range strings.Split(string(content), "\n") {
			if strings.Contains(line, "// indirect") {
				continue
			}
			if strings.Contains(line, fm.marker) {
				found = append(found, fm.framework)
				break
			}
		}
	}
	return found
}

func DetectFramework(projectPath string) string {
	frameworks := DetectFrameworks(projectPath)
	if len(frameworks) == 1 {
		return frameworks[0]
	}
	return ""
}

// detectFramework attempts to detect the framework being used
func (a *Analyzer) detectFramework() error {
	frameworks := DetectFrameworks(a.config.ProjectPath)
	if len(frameworks) > 1 && !a.config.Quiet {
		fmt.Fprintf(os.Stderr,
			"⚠️  Multiple frameworks detected in go.mod (%s) — pass --framework to disambiguate. Falling back to generic route detection.\n",
			strings.Join(frameworks, ", "))
	}
	if len(frameworks) != 1 {
		a.framework = models.FrameWorkUnknown
		return nil
	}
	a.framework = models.FrameWorkType(frameworks[0])
	return nil
}

// parseFile parses a Go file and extracts route information
func (a *Analyzer) parseFile(filePath string) error {
	fset := token.NewFileSet()
	node, err := a.rootParseFile(fset, filePath, parser.ParseComments)
	if err != nil {
		a.recordParseFailure(filePath, err)
		return nil // Skip files that can't be parsed
	}

	ast.Inspect(node, func(n ast.Node) bool {
		a.detectListenPort(n)
		return true
	})

	a.curFilePath = filePath

	a.curGroupPrefix = nil
	a.curAuthGroups = nil
	a.consumedCalls = nil
	switch a.framework {
	case models.FrameWorkGin, models.FrameWorkEcho, models.FrameWorkFiber:
		a.curGroupPrefix = a.buildGinGroupPrefixes(node)
		a.curAuthGroups = a.buildGinAuthGroups(node)
	case models.FrameWorkGorilla:
		a.curGroupPrefix = a.buildGorillaSubrouterPrefixes(node)
		a.curAuthGroups = a.buildGinAuthGroups(node) // .Use(...) detection is framework-agnostic
		a.consumedCalls = make(map[*ast.CallExpr]bool)
	case models.FrameWorkChi:

		for _, decl := range node.Decls {
			if fd, ok := decl.(*ast.FuncDecl); ok && fd.Body != nil {
				a.walkChiStmts(fd.Body.List, node, "", false)
			}
		}
		return nil
	}

	// Visit all nodes in the AST
	ast.Inspect(node, func(n ast.Node) bool {
		switch a.framework {
		case models.FrameWorkGin:
			a.parseGinRoutes(n, node)
		case models.FrameWorkEcho:
			a.parseEchoRoutes(n, node)
		case models.FrameWorkFiber:
			a.parseFiberRoutes(n, node)
		case models.FrameWorkGorilla:
			a.parseGorillaMethods(n, node)
			a.parseGorillaRoutes(n, node)
		default:
			a.parseGenericRoutes(n, node)
		}
		return true
	})

	return nil
}
