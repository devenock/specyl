package analyzer

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/devenock/specyl/pkg/models"
)

var bindMethodHints = []string{"bind", "decode", "unmarshal", "parse"}

var nonBodyBindMethods = map[string]bool{
	"ShouldBindQuery": true, "BindQuery": true,
	"ShouldBindUri": true, "BindUri": true,
	"ShouldBindHeader": true, "BindHeader": true,
}

func (a *Analyzer) findBindingTypeName(file *ast.File, funcName string) string {
	return a.findBindingTypeNameDepth(file, funcName, 0)
}

func (a *Analyzer) findBindingTypeNameDepth(file *ast.File, funcName string, depth int) string {
	bindMethods := map[string]bool{
		"ShouldBindJSON": true, "BindJSON": true,
		"ShouldBind": true, "Bind": true, "BodyParser": true,
		"Decode": true, "Unmarshal": true,
	}

	body := findFuncBody(file, funcName)
	if body == nil {
		return ""
	}
	varTypes, _, _, _ := collectLocalTypedVars(body)

	var result string
	ast.Inspect(body, func(n ast.Node) bool {
		if result != "" {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		exactName := calleeBaseName(call.Fun)
		if exactName == "" {
			exactName = calleeBaseName(genericBaseExpr(call.Fun))
		}
		if exactName != "" && nonBodyBindMethods[exactName] {
			return true
		}
		hintText := calleeHintText(call.Fun)
		if hintText == "" {
			hintText = calleeHintText(genericBaseExpr(call.Fun))
		}
		if !bindMethods[exactName] {
			if !hasBindHint(hintText) {
				return true
			}
			if a.config.Verbose {
				a.recordBindHintMatch(hintText)
			}
		}

		if typ := genericTypeArg(call.Fun); typ != "" {
			result = localTypeName(typ)
			return false
		}

		if len(call.Args) == 0 {
			return true
		}

		// Pattern 1: bindJSON(c, &req) / c.ShouldBindJSON(&req) — struct var is an argument.
		last := call.Args[len(call.Args)-1]
		if varName := identOrAddrIdentName(last); varName != "" && varTypes[varName] != "" {
			result = localTypeName(varTypes[varName])
			return false
		}
		// Pattern 2: req.Bind(c) — struct var is the method receiver.
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			if id, ok := sel.X.(*ast.Ident); ok && varTypes[id.Name] != "" {
				result = localTypeName(varTypes[id.Name])
				return false
			}
		}
		return true
	})
	if result != "" {
		return result
	}
	if depth >= 2 {
		return "" // cap delegation-chain recursion
	}
	return a.findDelegatedBindingTypeName(file, funcName, depth)
}

func (a *Analyzer) findDelegatedBindingTypeName(file *ast.File, funcName string, depth int) string {
	var fd *ast.FuncDecl
	for _, decl := range file.Decls {
		if f, ok := decl.(*ast.FuncDecl); ok && f.Name.Name == funcName && f.Body != nil {
			fd = f
			break
		}
	}
	if fd == nil || fd.Recv == nil || len(fd.Recv.List) == 0 || len(fd.Recv.List[0].Names) == 0 {
		return ""
	}
	recvName := fd.Recv.List[0].Names[0].Name
	if recvName == "" {
		return ""
	}

	var delegateFunc string
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if delegateFunc != "" {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok && id.Name == recvName {
			delegateFunc = sel.Sel.Name
		}
		return true
	})
	if delegateFunc == "" || delegateFunc == funcName {
		return ""
	}
	return a.findBindingTypeNameDepth(file, delegateFunc, depth+1)
}

func (a *Analyzer) responseBodyIdentNames(fd *ast.FuncDecl, recvName string) map[string]bool {
	names := make(map[string]bool)
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		var bodyExpr ast.Expr
		if a.usesNetHTTPHandlers() {
			bodyExpr, _ = matchJSONEncode(call, recvName)
		} else if rc, ok := a.recognizeResponseCall(call, recvName, nil); ok && rc.hasBody {
			bodyExpr = rc.bodyExpr
		}
		if id, ok := bodyExpr.(*ast.Ident); ok {
			names[id.Name] = true
		}
		return true
	})
	return names
}

func (a *Analyzer) findAddressTakenStructVar(file *ast.File, funcName string) string {
	fd := findFuncDecl(file, funcName)
	if fd == nil || fd.Body == nil {
		return ""
	}
	varTypes, order, addressTaken, typeAsserted := collectLocalTypedVars(fd.Body)

	var excluded map[string]bool
	if recvName := firstParamName(fd); recvName != "" {
		excluded = a.responseBodyIdentNames(fd, recvName)
	}

	for _, name := range order {
		if !addressTaken[name] && !typeAsserted[name] {
			continue
		}
		if excluded[name] {
			continue
		}
		return localTypeName(varTypes[name])
	}
	return ""
}

func (a *Analyzer) findLocalStructType(file *ast.File, funcName, typeName string) (models.Schema, bool) {
	body := findFuncBody(file, funcName)
	if body == nil {
		return models.Schema{}, false
	}
	var found *ast.StructType
	ast.Inspect(body, func(n ast.Node) bool {
		if found != nil {
			return false
		}
		genDecl, ok := n.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.TYPE {
			return true
		}
		for _, spec := range genDecl.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok || typeSpec.Name.Name != typeName {
				continue
			}
			if st, ok := typeSpec.Type.(*ast.StructType); ok {
				found = st
			}
		}
		return true
	})
	if found == nil {
		return models.Schema{}, false
	}
	return a.buildSchemaFromStruct(found), true
}

func (a *Analyzer) resolveRequestSchema(file *ast.File, funcName, typeName string) (schema models.Schema, ok bool, isLocal bool) {
	if schema, ok := a.typeRegistry[typeName]; ok {
		return schema, true, false
	}
	localSchema, localOk := a.findLocalStructType(file, funcName, typeName)
	return localSchema, localOk, true
}

func findFuncBody(file *ast.File, funcName string) *ast.BlockStmt {
	for _, decl := range file.Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name.Name == funcName && fd.Body != nil {
			return fd.Body
		}
	}
	return nil
}

func collectLocalTypedVars(body *ast.BlockStmt) (varTypes map[string]string, order []string, addressTaken map[string]bool, typeAsserted map[string]bool) {
	varTypes = make(map[string]string)
	addressTaken = make(map[string]bool)
	typeAsserted = make(map[string]bool)
	recordVar := func(name, typ string) {
		if typ == "" {
			return
		}
		if _, seen := varTypes[name]; !seen {
			order = append(order, name)
		}
		varTypes[name] = typ
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch s := n.(type) {
		// var req LoginRequest
		case *ast.GenDecl:
			if s.Tok == token.VAR {
				for _, spec := range s.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok || vs.Type == nil {
						continue
					}
					name := typeExprToName(vs.Type)
					for _, id := range vs.Names {
						recordVar(id.Name, name)
					}
				}
			}
		// req := LoginRequest{} / req := &LoginRequest{} / req := new(LoginRequest) / req := v.(*LoginRequest)
		case *ast.AssignStmt:
			for i, rhs := range s.Rhs {
				if i >= len(s.Lhs) {
					break
				}
				lhs, ok := s.Lhs[i].(*ast.Ident)
				if !ok {
					continue
				}
				switch expr := rhs.(type) {
				case *ast.CompositeLit:
					if expr.Type != nil {
						recordVar(lhs.Name, typeExprToName(expr.Type))
					}
				case *ast.UnaryExpr:
					if expr.Op == token.AND {
						if cl, ok := expr.X.(*ast.CompositeLit); ok && cl.Type != nil {
							recordVar(lhs.Name, typeExprToName(cl.Type))
						}
					}
				case *ast.CallExpr:
					if id, ok := expr.Fun.(*ast.Ident); ok && id.Name == "new" && len(expr.Args) == 1 {
						recordVar(lhs.Name, typeExprToName(expr.Args[0]))
					}
				case *ast.TypeAssertExpr:
					if expr.Type != nil {
						recordVar(lhs.Name, typeExprToName(expr.Type))
						typeAsserted[lhs.Name] = true
					}
				}
			}
		case *ast.UnaryExpr:
			if s.Op == token.AND {
				if id, ok := s.X.(*ast.Ident); ok {
					addressTaken[id.Name] = true
				}
			}
		}
		return true
	})
	return
}

func identOrAddrIdentName(e ast.Expr) string {
	switch a := e.(type) {
	case *ast.UnaryExpr:
		if a.Op == token.AND {
			if id, ok := a.X.(*ast.Ident); ok {
				return id.Name
			}
		}
	case *ast.Ident:
		return a.Name
	}
	return ""
}

func calleeBaseName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return x.Sel.Name
	}
	return ""
}

func calleeHintText(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		if id, ok := x.X.(*ast.Ident); ok {
			return id.Name + "." + x.Sel.Name
		}
		return x.Sel.Name
	}
	return ""
}

func hasBindHint(text string) bool {
	if text == "" {
		return false
	}
	lower := strings.ToLower(text)
	for _, hint := range bindMethodHints {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}

func genericBaseExpr(fun ast.Expr) ast.Expr {
	switch f := fun.(type) {
	case *ast.IndexExpr:
		return f.X
	case *ast.IndexListExpr:
		return f.X
	}
	return nil
}

func genericTypeArg(fun ast.Expr) string {
	switch f := fun.(type) {
	case *ast.IndexExpr:
		return typeExprToName(f.Index)
	case *ast.IndexListExpr:
		if len(f.Indices) > 0 {
			return typeExprToName(f.Indices[0])
		}
	}
	return ""
}

func extractQueryParams(file *ast.File, funcName string) []models.Parameter {
	queryMethods := map[string]bool{
		"Query": true, "DefaultQuery": true, "QueryParam": true,
	}

	var body *ast.BlockStmt
	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if ok && fd.Name.Name == funcName && fd.Body != nil {
			body = fd.Body
			break
		}
	}
	if body == nil {
		return nil
	}

	seen := make(map[string]bool)
	var params []models.Parameter
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}

		var name string
		switch {
		case queryMethods[sel.Sel.Name]:
			if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
				name = strings.Trim(lit.Value, `"`)
			}
		case sel.Sel.Name == "Get":
			// r.URL.Query().Get("name") / req.URL.Query().Get("name")
			inner, ok := sel.X.(*ast.CallExpr)
			if !ok {
				return true
			}
			innerSel, ok := inner.Fun.(*ast.SelectorExpr)
			if !ok || innerSel.Sel.Name != "Query" {
				return true
			}
			if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
				name = strings.Trim(lit.Value, `"`)
			}
		}

		if name != "" && !seen[name] {
			seen[name] = true
			params = append(params, models.Parameter{
				Name:     name,
				In:       "query",
				Required: false,
				Schema:   models.Schema{Type: "string"},
			})
		}
		return true
	})
	return params
}
