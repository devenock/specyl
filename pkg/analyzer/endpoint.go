package analyzer

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/devenock/specyl/pkg/models"
)

var errStopWalk = errors.New("stop walk")

func (a *Analyzer) finishEndpoint(ep *models.Endpoint, handlerArg ast.Expr, file *ast.File) {
	var handlerName, handlerPkg string
	switch h := handlerArg.(type) {
	case *ast.Ident:
		handlerName = h.Name
	case *ast.SelectorExpr:
		if pkgIdent, ok := h.X.(*ast.Ident); ok {
			// Single-level: handlers.CreateUser  or  userHandler.CreateUser
			handlerPkg = pkgIdent.Name
			handlerName = h.Sel.Name
		} else if _, ok := h.X.(*ast.SelectorExpr); ok {

			handlerName = h.Sel.Name
			handlerPkg = "_"
		}
	}

	if handlerName != "" {
		ep.Summary = handlerName
		// Same-file handler: get comments and request/response types from current file
		if handlerPkg == "" {
			a.extractHandlerComments(file, handlerName, ep)
			reqTypeName, respTypeName := getHandlerRequestAndResponseTypes(file, handlerName)

			if reqTypeName == "" {
				reqTypeName = a.findBindingTypeName(file, handlerName)
			}

			if reqTypeName == "" && (ep.Method == "POST" || ep.Method == "PUT" || ep.Method == "PATCH") {
				reqTypeName = a.findAddressTakenStructVar(file, handlerName)
			}
			if reqTypeName != "" {
				reqTypeName = localTypeName(reqTypeName)
				if schema, ok, isLocal := a.resolveRequestSchema(file, handlerName, reqTypeName); ok {
					ep.RequestTypeName = reqTypeName
					if !isLocal {
						a.addSchemaAndRefsToModels(reqTypeName, schema)
					}
					ep.RequestBody = &models.RequestBody{
						Required: true,
						Content: map[string]models.Content{
							"application/json": {Schema: schema},
						},
					}
				}
			}
			if respTypeName != "" {
				respTypeName = localTypeName(respTypeName)
				if schema, ok, isLocal := a.resolveRequestSchema(file, handlerName, respTypeName); ok {
					ep.ResponseTypeName = respTypeName
					if !isLocal {
						a.addSchemaAndRefsToModels(respTypeName, schema)
					}
					ep.Responses[200] = models.Response{
						Description: "Successful response",
						Content: map[string]models.Content{
							"application/json": {Schema: schema},
						},
					}
				}
			}

			for status, resp := range a.extractResponses(file, handlerName) {
				ep.Responses[status] = resp
			}
			ep.Parameters = append(ep.Parameters, extractQueryParams(file, handlerName)...)
		}

	}

	// Description/summary fallback when no comment
	if ep.Description == "" && handlerName != "" {
		ep.Description = humanizeHandlerName(handlerName)
	}
	if ep.Summary == handlerName && handlerName != "" {
		ep.Summary = humanizeHandlerName(handlerName)
	}

	// For --write-annotations: record handler location (same file or package to resolve later)
	if handlerName != "" {
		ep.HandlerName = handlerName
		ep.HandlerPackage = handlerPkg
		if handlerPkg == "" && a.curFilePath != "" {
			ep.SourceFile = a.curFilePath
		}
	}
}

func (a *Analyzer) resolveHandlerSourceFiles() {
	for i := range a.endpoints {
		ep := &a.endpoints[i]
		if ep.HandlerName == "" || ep.SourceFile != "" {
			continue
		}
		if ep.HandlerPackage == "" {
			continue
		}
		filePath := a.findFileWithFunction(ep.HandlerPackage, ep.HandlerName)
		if filePath != "" {
			ep.SourceFile = filePath
			// Parse with comments so extractHandlerComments can read doc blocks.
			fset := token.NewFileSet()
			node, err := a.rootParseFile(fset, filePath, parser.ParseComments)
			if err == nil {
				// Extract the doc comment — overrides the humanized-name fallback.
				a.extractHandlerComments(node, ep.HandlerName, ep)

				// Scan the body for JSON-binding calls to get the request body type.
				if ep.RequestBody == nil {
					typName := a.findBindingTypeName(node, ep.HandlerName)
					if typName == "" && (ep.Method == "POST" || ep.Method == "PUT" || ep.Method == "PATCH") {
						typName = a.findAddressTakenStructVar(node, ep.HandlerName)
					}
					if typName != "" {
						if schema, ok, isLocal := a.resolveRequestSchema(node, ep.HandlerName, typName); ok {
							ep.RequestTypeName = typName
							if !isLocal {
								a.addSchemaAndRefsToModels(typName, schema)
							}
							ep.RequestBody = &models.RequestBody{
								Required: true,
								Content: map[string]models.Content{
									"application/json": {Schema: schema},
								},
							}
						}
					}
				}
				if len(ep.Responses) == 0 {
					for status, resp := range a.extractResponses(node, ep.HandlerName) {
						ep.Responses[status] = resp
					}
				}
				ep.Parameters = append(ep.Parameters, extractQueryParams(node, ep.HandlerName)...)
			}
		}
	}
}

func (a *Analyzer) resolveRemainingResponses() {
	for i := range a.endpoints {
		ep := &a.endpoints[i]
		if len(ep.Responses) != 0 || ep.HandlerName == "" {
			continue
		}

		if ep.SourceFile != "" {
			fset := token.NewFileSet()
			if node, err := a.rootParseFile(fset, ep.SourceFile, 0); err == nil {
				for status, resp := range a.extractResponses(node, ep.HandlerName) {
					ep.Responses[status] = resp
				}
			}
			if len(ep.Responses) != 0 {
				continue
			}
		}

		_ = a.walkProjectDir(func(path string, d fs.DirEntry) error {
			if len(ep.Responses) != 0 {
				return nil
			}
			if d.IsDir() {
				for _, ex := range a.config.Exclude {
					if filepath.Base(path) == ex {
						return filepath.SkipDir
					}
				}
				return nil
			}
			if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") || path == ep.SourceFile {
				return nil
			}
			raw, readErr := a.rootReadFile(path)
			if readErr != nil || !strings.Contains(string(raw), " "+ep.HandlerName+"(") {
				return nil
			}
			fset := token.NewFileSet()
			node, err := a.rootParseFile(fset, path, 0)
			if err != nil {
				return nil
			}
			for status, resp := range a.extractResponses(node, ep.HandlerName) {
				ep.Responses[status] = resp
			}
			if len(ep.Responses) != 0 {
				return errStopWalk
			}
			return nil
		})
	}
}

func (a *Analyzer) resolveRemainingRequestBodies() {
	for i := range a.endpoints {
		ep := &a.endpoints[i]
		if ep.RequestBody != nil || ep.HandlerName == "" {
			continue
		}
		if ep.Method != "POST" && ep.Method != "PUT" && ep.Method != "PATCH" {
			continue
		}

		// 1. Try the already-known source file first (cheapest).
		if ep.SourceFile != "" {
			if a.extractBodyFromFile(ep, ep.SourceFile) {
				continue
			}
		}

		_ = a.walkProjectDir(func(path string, d fs.DirEntry) error {
			if ep.RequestBody != nil {
				return nil
			}
			if d.IsDir() {
				for _, ex := range a.config.Exclude {
					if filepath.Base(path) == ex {
						return filepath.SkipDir
					}
				}
				return nil
			}
			if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") || path == ep.SourceFile {
				return nil
			}
			raw, readErr := a.rootReadFile(path)
			if readErr != nil {
				return nil
			}
			content := string(raw)

			if !strings.Contains(content, " "+ep.HandlerName+"(") {
				return nil
			}
			if a.extractBodyFromFile(ep, path) {

				ep.SourceFile = path
				return errStopWalk
			}
			return nil
		})
	}
}

func (a *Analyzer) extractBodyFromFile(ep *models.Endpoint, filePath string) bool {
	fset := token.NewFileSet()
	node, err := a.rootParseFile(fset, filePath, 0)
	if err != nil {
		return false
	}
	typName := a.findBindingTypeName(node, ep.HandlerName)
	if typName == "" {
		typName = a.findAddressTakenStructVar(node, ep.HandlerName)
	}
	if typName == "" {
		return false
	}
	schema, ok, isLocal := a.resolveRequestSchema(node, ep.HandlerName, typName)
	if !ok {
		return false
	}
	ep.RequestTypeName = typName
	if !isLocal {
		a.addSchemaAndRefsToModels(typName, schema)
	}
	ep.RequestBody = &models.RequestBody{
		Required: true,
		Content: map[string]models.Content{
			"application/json": {Schema: schema},
		},
	}
	return true
}

func (a *Analyzer) findFileWithFunction(pkgName, funcName string) string {
	skipDir := func(path string) bool {
		for _, ex := range a.config.Exclude {
			if filepath.Base(path) == ex {
				return true
			}
		}
		return false
	}

	// Pass 1: match by package declaration or directory name.
	var found string
	_ = a.walkProjectDir(func(path string, d fs.DirEntry) error {
		if d.IsDir() {
			if skipDir(path) {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		node, err := a.rootParseFile(fset, path, 0)
		if err != nil {
			return nil
		}
		pkgDecl := node.Name.Name
		dirName := filepath.Base(filepath.Dir(path))
		if pkgDecl != pkgName && dirName != pkgName {
			return nil
		}
		for _, decl := range node.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Name.Name != funcName {
				continue
			}
			found = path
			return errStopWalk
		}
		return nil
	})
	if found != "" {
		return found
	}

	// Pass 2: pkgName may be a variable/instance — search all files by function name using a fast text pre-filter.
	_ = a.walkProjectDir(func(path string, d fs.DirEntry) error {
		if found != "" {
			return nil
		}
		if d.IsDir() {
			if skipDir(path) {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		raw, readErr := a.rootReadFile(path)
		if readErr != nil || !strings.Contains(string(raw), " "+funcName+"(") {
			return nil
		}
		fset := token.NewFileSet()
		node, err := a.rootParseFile(fset, path, 0)
		if err != nil {
			return nil
		}
		for _, decl := range node.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Name.Name != funcName {
				continue
			}
			found = path
			return errStopWalk
		}
		return nil
	})
	return found
}

// extractHandlerComments extracts comments from handler functions
func (a *Analyzer) extractHandlerComments(file *ast.File, handlerName string, endpoint *models.Endpoint) {
	for _, decl := range file.Decls {
		funcDecl, ok := decl.(*ast.FuncDecl)
		if !ok || funcDecl.Name.Name != handlerName {
			continue
		}

		if funcDecl.Doc != nil {
			var docLines []string
			for _, comment := range funcDecl.Doc.List {
				text := strings.TrimPrefix(comment.Text, "//")
				text = strings.TrimSpace(text)
				if text != "" {
					docLines = append(docLines, text)
				}
			}
			if len(docLines) > 0 {
				// Summary = first comment line (the short one-liner above the func).
				endpoint.Summary = docLines[0]
				// Description = all lines joined — gives full context in the spec.
				endpoint.Description = strings.Join(docLines, " ")
			}
		}
		break
	}
}

// deduplicateEndpoints keeps first occurrence of each (method, path).
func (a *Analyzer) deduplicateEndpoints(endpoints []models.Endpoint) []models.Endpoint {
	seen := make(map[string]bool)
	var out []models.Endpoint
	for _, ep := range endpoints {
		key := ep.Method + " " + ep.Path
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ep)
	}
	return out
}

func (a *Analyzer) filterEndpointsByTags(endpoints []models.Endpoint) []models.Endpoint {
	if len(a.config.Tags) == 0 {
		return endpoints
	}
	var include, exclude []string
	for _, f := range a.config.Tags {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if strings.HasPrefix(f, "!") {
			exclude = append(exclude, strings.TrimPrefix(f, "!"))
		} else {
			include = append(include, f)
		}
	}
	hasAny := func(epTags, filterTags []string) bool {
		for _, want := range filterTags {
			for _, epTag := range epTags {
				if epTag == want {
					return true
				}
			}
		}
		return false
	}
	var out []models.Endpoint
	for _, ep := range endpoints {
		if hasAny(ep.Tags, exclude) {
			continue
		}
		if len(include) > 0 && !hasAny(ep.Tags, include) {
			continue
		}
		out = append(out, ep)
	}
	return out
}
