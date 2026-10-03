package analyzer

import (
	"fmt"
	"go/ast"
	"go/token"
	"net/http"
	"strconv"
	"strings"

	"github.com/devenock/specyl/pkg/models"
)

type responseCall struct {
	status   int
	hasBody  bool
	isJSON   bool
	bodyExpr ast.Expr
}

// Per-framework response-emitting method tables (review §3, Step 1).
var (
	ginJSONResponseMethods = map[string]bool{
		"JSON": true, "IndentedJSON": true, "PureJSON": true,
		"SecureJSON": true, "AsciiJSON": true, "AbortWithStatusJSON": true,
	}
	ginNonJSONResponseMethods  = map[string]bool{"String": true, "Data": true, "XML": true}
	ginBodylessResponseMethods = map[string]bool{"Status": true, "AbortWithStatus": true}

	echoJSONResponseMethods    = map[string]bool{"JSON": true, "JSONPretty": true}
	echoNonJSONResponseMethods = map[string]bool{"String": true, "Blob": true}
	echoBodylessResponseMethod = "NoContent"
)

var httpStatusConstants = map[string]int{
	"StatusContinue": 100, "StatusSwitchingProtocols": 101, "StatusProcessing": 102,
	"StatusOK": 200, "StatusCreated": 201, "StatusAccepted": 202,
	"StatusNonAuthoritativeInfo": 203, "StatusNoContent": 204, "StatusResetContent": 205,
	"StatusPartialContent": 206, "StatusMultiStatus": 207, "StatusAlreadyReported": 208,
	"StatusIMUsed":          226,
	"StatusMultipleChoices": 300, "StatusMovedPermanently": 301, "StatusFound": 302,
	"StatusSeeOther": 303, "StatusNotModified": 304, "StatusUseProxy": 305,
	"StatusTemporaryRedirect": 307, "StatusPermanentRedirect": 308,
	"StatusBadRequest": 400, "StatusUnauthorized": 401, "StatusPaymentRequired": 402,
	"StatusForbidden": 403, "StatusNotFound": 404, "StatusMethodNotAllowed": 405,
	"StatusNotAcceptable": 406, "StatusProxyAuthRequired": 407, "StatusRequestTimeout": 408,
	"StatusConflict": 409, "StatusGone": 410, "StatusLengthRequired": 411,
	"StatusPreconditionFailed": 412, "StatusRequestEntityTooLarge": 413,
	"StatusRequestURITooLong": 414, "StatusUnsupportedMediaType": 415,
	"StatusRequestedRangeNotSatisfiable": 416, "StatusExpectationFailed": 417,
	"StatusTeapot": 418, "StatusMisdirectedRequest": 421, "StatusUnprocessableEntity": 422,
	"StatusLocked": 423, "StatusFailedDependency": 424, "StatusTooEarly": 425,
	"StatusUpgradeRequired": 426, "StatusPreconditionRequired": 428,
	"StatusTooManyRequests": 429, "StatusRequestHeaderFieldsTooLarge": 431,
	"StatusUnavailableForLegalReasons": 451,
	"StatusInternalServerError":        500, "StatusNotImplemented": 501, "StatusBadGateway": 502,
	"StatusServiceUnavailable": 503, "StatusGatewayTimeout": 504,
	"StatusHTTPVersionNotSupported": 505, "StatusVariantAlsoNegotiates": 506,
	"StatusInsufficientStorage": 507, "StatusLoopDetected": 508,
	"StatusNotExtended": 510, "StatusNetworkAuthenticationRequired": 511,
}

func statusDescription(status int) string {
	if status >= 200 && status < 300 {
		return "Successful response"
	}
	if text := http.StatusText(status); text != "" {
		return text
	}
	return fmt.Sprintf("Response %d", status)
}

// resolveStatusCode resolves a call argument to an HTTP status code
func resolveStatusCode(expr ast.Expr) (int, bool) {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind != token.INT {
			return 0, false
		}
		n, err := strconv.Atoi(e.Value)
		if err != nil {
			return 0, false
		}
		return n, true
	case *ast.SelectorExpr:
		pkgIdent, ok := e.X.(*ast.Ident)

		if !ok || (pkgIdent.Name != "http" && pkgIdent.Name != "fiber") {
			return 0, false
		}
		code, ok := httpStatusConstants[e.Sel.Name]
		return code, ok
	}
	return 0, false
}

func substArg(expr ast.Expr, subst map[string]ast.Expr) ast.Expr {
	if subst == nil {
		return expr
	}
	id, ok := expr.(*ast.Ident)
	if !ok {
		return expr
	}
	if replacement, ok := subst[id.Name]; ok {
		return replacement
	}
	return expr
}

// usesNetHTTPHandlers reports whether handlers are plain func(http.ResponseWriter, *http.Request) — true for Gorilla, Chi, and the generic net/http fallback.
func (a *Analyzer) usesNetHTTPHandlers() bool {
	switch a.framework {
	case models.FrameWorkGorilla, models.FrameWorkChi, models.FrameWorkUnknown:
		return true
	}
	return false
}

func (a *Analyzer) recognizeResponseCall(call *ast.CallExpr, recvName string, subst map[string]ast.Expr) (responseCall, bool) {
	switch a.framework {
	case models.FrameWorkGin:
		return recognizeGinResponseCall(call, recvName, subst)
	case models.FrameWorkEcho:
		return recognizeEchoResponseCall(call, recvName, subst)
	case models.FrameWorkFiber:
		return recognizeFiberResponseCall(call, recvName, subst)
	}
	return responseCall{}, false
}

func recognizeGinResponseCall(call *ast.CallExpr, recvName string, subst map[string]ast.Expr) (responseCall, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return responseCall{}, false
	}
	recv, ok := sel.X.(*ast.Ident)
	if !ok || recv.Name != recvName {
		return responseCall{}, false
	}
	method := sel.Sel.Name

	switch {
	case ginJSONResponseMethods[method]:
		if len(call.Args) < 2 {
			return responseCall{}, false
		}
		status, ok := resolveStatusCode(substArg(call.Args[0], subst))
		if !ok {
			return responseCall{}, false
		}
		return responseCall{status: status, hasBody: true, isJSON: true, bodyExpr: substArg(call.Args[1], subst)}, true
	case ginNonJSONResponseMethods[method]:
		if len(call.Args) < 1 {
			return responseCall{}, false
		}
		status, ok := resolveStatusCode(substArg(call.Args[0], subst))
		if !ok {
			return responseCall{}, false
		}
		return responseCall{status: status, hasBody: true, isJSON: false}, true
	case ginBodylessResponseMethods[method]:
		if len(call.Args) < 1 {
			return responseCall{}, false
		}
		status, ok := resolveStatusCode(substArg(call.Args[0], subst))
		if !ok {
			return responseCall{}, false
		}
		return responseCall{status: status, hasBody: false}, true
	}
	return responseCall{}, false
}

func recognizeEchoResponseCall(call *ast.CallExpr, recvName string, subst map[string]ast.Expr) (responseCall, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return responseCall{}, false
	}
	recv, ok := sel.X.(*ast.Ident)
	if !ok || recv.Name != recvName {
		return responseCall{}, false
	}
	method := sel.Sel.Name

	switch {
	case echoJSONResponseMethods[method]:
		if len(call.Args) < 2 {
			return responseCall{}, false
		}
		status, ok := resolveStatusCode(substArg(call.Args[0], subst))
		if !ok {
			return responseCall{}, false
		}
		return responseCall{status: status, hasBody: true, isJSON: true, bodyExpr: substArg(call.Args[1], subst)}, true
	case echoNonJSONResponseMethods[method]:
		if len(call.Args) < 1 {
			return responseCall{}, false
		}
		status, ok := resolveStatusCode(substArg(call.Args[0], subst))
		if !ok {
			return responseCall{}, false
		}
		return responseCall{status: status, hasBody: true, isJSON: false}, true
	case method == echoBodylessResponseMethod:
		if len(call.Args) < 1 {
			return responseCall{}, false
		}
		status, ok := resolveStatusCode(substArg(call.Args[0], subst))
		if !ok {
			return responseCall{}, false
		}
		return responseCall{status: status, hasBody: false}, true
	}
	return responseCall{}, false
}

func recognizeFiberResponseCall(call *ast.CallExpr, recvName string, subst map[string]ast.Expr) (responseCall, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return responseCall{}, false
	}
	method := sel.Sel.Name

	if recv, ok := sel.X.(*ast.Ident); ok && recv.Name == recvName {
		switch method {
		case "JSON":
			if len(call.Args) < 1 {
				return responseCall{}, false
			}
			return responseCall{status: 200, hasBody: true, isJSON: true, bodyExpr: substArg(call.Args[0], subst)}, true
		case "SendString":
			return responseCall{status: 200, hasBody: true, isJSON: false}, true
		case "SendStatus":
			if len(call.Args) < 1 {
				return responseCall{}, false
			}
			status, ok := resolveStatusCode(substArg(call.Args[0], subst))
			if !ok {
				return responseCall{}, false
			}
			return responseCall{status: status, hasBody: false}, true
		}
		return responseCall{}, false
	}

	inner, ok := sel.X.(*ast.CallExpr)
	if !ok {
		return responseCall{}, false
	}
	innerSel, ok := inner.Fun.(*ast.SelectorExpr)
	if !ok || innerSel.Sel.Name != "Status" {
		return responseCall{}, false
	}
	innerRecv, ok := innerSel.X.(*ast.Ident)
	if !ok || innerRecv.Name != recvName || len(inner.Args) < 1 {
		return responseCall{}, false
	}
	status, ok := resolveStatusCode(substArg(inner.Args[0], subst))
	if !ok {
		return responseCall{}, false
	}
	switch method {
	case "JSON":
		if len(call.Args) < 1 {
			return responseCall{}, false
		}
		return responseCall{status: status, hasBody: true, isJSON: true, bodyExpr: substArg(call.Args[0], subst)}, true
	case "SendString":
		return responseCall{status: status, hasBody: true, isJSON: false}, true
	}
	return responseCall{}, false
}

func isMapLikeLiteralType(t ast.Expr) bool {
	switch e := t.(type) {
	case *ast.MapType:
		return true
	case *ast.SelectorExpr:
		return e.Sel.Name == "H" || e.Sel.Name == "Map"
	}
	return false
}

func schemaFromMapLiteralKeys(lit *ast.CompositeLit) models.Schema {
	props := make(map[string]models.Schema)
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		keyLit, ok := kv.Key.(*ast.BasicLit)
		if !ok || keyLit.Kind != token.STRING {
			continue
		}
		props[strings.Trim(keyLit.Value, `"`)] = models.Schema{Type: "string"}
	}
	return models.Schema{Type: "object", Properties: props}
}

func findFuncDecl(file *ast.File, funcName string) *ast.FuncDecl {
	for _, decl := range file.Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name.Name == funcName {
			return fd
		}
	}
	return nil
}

func resolveCallReturnTypeName(file *ast.File, call *ast.CallExpr) string {
	name := calleeBaseName(call.Fun)
	if name == "" {
		return ""
	}
	fd := findFuncDecl(file, name)
	if fd == nil || fd.Type.Results == nil {
		return ""
	}
	for _, res := range fd.Type.Results.List {
		typeName := typeExprToName(res.Type)
		if typeName == "" || typeName == "error" {
			continue
		}
		return typeName
	}
	return ""
}

func findIdentAssignedCallType(file *ast.File, body *ast.BlockStmt, name string) string {
	var result string
	ast.Inspect(body, func(n ast.Node) bool {
		if result != "" {
			return false
		}
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, lhs := range assign.Lhs {
			id, ok := lhs.(*ast.Ident)
			if !ok || id.Name != name || i >= len(assign.Rhs) {
				continue
			}
			if call, ok := assign.Rhs[i].(*ast.CallExpr); ok {
				if typ := resolveCallReturnTypeName(file, call); typ != "" {
					result = typ
				}
			}
		}
		return true
	})
	return result
}

// resolveResponseBodySchema resolves the OpenAPI schema
func (a *Analyzer) resolveResponseBodySchema(file *ast.File, funcName string, expr ast.Expr, body *ast.BlockStmt, varTypes map[string]string) (schema models.Schema, typeName string) {
	switch e := expr.(type) {
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			return a.resolveResponseBodySchema(file, funcName, e.X, body, varTypes)
		}
	case *ast.CompositeLit:
		if e.Type == nil {
			return models.Schema{Type: "object"}, ""
		}
		if isMapLikeLiteralType(e.Type) {
			return schemaFromMapLiteralKeys(e), ""
		}
		name := localTypeName(typeExprToName(e.Type))
		if resolved, ok, isLocal := a.resolveRequestSchema(file, funcName, name); ok {
			if isLocal {
				return resolved, ""
			}
			return resolved, name
		}
		return models.Schema{Type: "object"}, ""
	case *ast.Ident:
		typ := varTypes[e.Name]
		if typ == "" {
			typ = findIdentAssignedCallType(file, body, e.Name)
		}
		if typ != "" {
			name := localTypeName(typ)
			if resolved, ok, isLocal := a.resolveRequestSchema(file, funcName, name); ok {
				if isLocal {
					return resolved, ""
				}
				return resolved, name
			}
		}
	case *ast.CallExpr:
		if typ := resolveCallReturnTypeName(file, e); typ != "" {
			name := localTypeName(typ)
			if resolved, ok, isLocal := a.resolveRequestSchema(file, funcName, name); ok {
				if isLocal {
					return resolved, ""
				}
				return resolved, name
			}
		}
	}
	return models.Schema{Type: "object"}, ""
}

func (a *Analyzer) recordResponseCall(file *ast.File, funcName string, rc responseCall, body *ast.BlockStmt, varTypes map[string]string, responses map[int]models.Response) {
	if !rc.hasBody || !rc.isJSON {
		responses[rc.status] = models.Response{Description: statusDescription(rc.status)}
		return
	}
	schema, typeName := a.resolveResponseBodySchema(file, funcName, rc.bodyExpr, body, varTypes)
	if typeName != "" {
		a.addSchemaAndRefsToModels(typeName, schema)
	}
	responses[rc.status] = models.Response{
		Description: statusDescription(rc.status),
		Content: map[string]models.Content{
			"application/json": {Schema: schema},
		},
	}
}

func firstParamName(fd *ast.FuncDecl) string {
	if fd.Type.Params == nil || len(fd.Type.Params.List) == 0 {
		return ""
	}
	first := fd.Type.Params.List[0]
	if len(first.Names) == 0 {
		return ""
	}
	return first.Names[0].Name
}

// matchWriteHeader recognizes w.WriteHeader(status) and resolves status.
func matchWriteHeader(call *ast.CallExpr, writerName string) (int, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "WriteHeader" || len(call.Args) < 1 {
		return 0, false
	}
	recv, ok := sel.X.(*ast.Ident)
	if !ok || recv.Name != writerName {
		return 0, false
	}
	return resolveStatusCode(call.Args[0])
}

// matchJSONEncode recognizes json.NewEncoder(w).Encode(v) and returns v.
func matchJSONEncode(call *ast.CallExpr, writerName string) (ast.Expr, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Encode" || len(call.Args) < 1 {
		return nil, false
	}
	inner, ok := sel.X.(*ast.CallExpr)
	if !ok {
		return nil, false
	}
	innerSel, ok := inner.Fun.(*ast.SelectorExpr)
	if !ok || innerSel.Sel.Name != "NewEncoder" || len(inner.Args) < 1 {
		return nil, false
	}
	pkgIdent, ok := innerSel.X.(*ast.Ident)
	if !ok || pkgIdent.Name != "json" {
		return nil, false
	}
	argIdent, ok := inner.Args[0].(*ast.Ident)
	if !ok || argIdent.Name != writerName {
		return nil, false
	}
	return call.Args[0], true
}

func (a *Analyzer) walkNetHTTPResponses(file *ast.File, funcName string, fd *ast.FuncDecl, writerName string, varTypes map[string]string, responses map[int]models.Response) {
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		block, ok := n.(*ast.BlockStmt)
		if !ok {
			return true
		}
		status := 200 // net/http's default if WriteHeader is never called
		for _, stmt := range block.List {
			exprStmt, ok := stmt.(*ast.ExprStmt)
			if !ok {
				continue
			}
			call, ok := exprStmt.X.(*ast.CallExpr)
			if !ok {
				continue
			}
			if s, ok := matchWriteHeader(call, writerName); ok {
				status = s
				if _, has := responses[status]; !has {

					responses[status] = models.Response{Description: statusDescription(status)}
				}
				continue
			}
			if bodyExpr, ok := matchJSONEncode(call, writerName); ok {
				schema, typeName := a.resolveResponseBodySchema(file, funcName, bodyExpr, block, varTypes)
				if typeName != "" {
					a.addSchemaAndRefsToModels(typeName, schema)
				}
				responses[status] = models.Response{
					Description: statusDescription(status),
					Content: map[string]models.Content{
						"application/json": {Schema: schema},
					},
				}
			}
		}
		return true
	})
}

func isContextPassthroughCall(call *ast.CallExpr, recvName string) bool {
	if len(call.Args) == 0 {
		return false
	}
	id, ok := call.Args[0].(*ast.Ident)
	if !ok || id.Name != recvName {
		return false
	}
	switch call.Fun.(type) {
	case *ast.Ident, *ast.SelectorExpr:
		return true
	}
	return false
}

func flattenParamNames(fl *ast.FieldList) []string {
	if fl == nil {
		return nil
	}
	var names []string
	for _, f := range fl.List {
		if len(f.Names) == 0 {
			names = append(names, "")
			continue
		}
		for _, n := range f.Names {
			names = append(names, n.Name)
		}
	}
	return names
}

func (a *Analyzer) resolveHelperDelegate(file *ast.File, callerFd *ast.FuncDecl, call *ast.CallExpr) (delegateName string, subst map[string]ast.Expr) {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		delegateName = fn.Name
	case *ast.SelectorExpr:
		if callerFd.Recv == nil || len(callerFd.Recv.List) == 0 || len(callerFd.Recv.List[0].Names) == 0 {
			return "", nil
		}
		ownRecv := callerFd.Recv.List[0].Names[0].Name
		id, ok := fn.X.(*ast.Ident)
		if !ok || id.Name != ownRecv {
			return "", nil
		}
		delegateName = fn.Sel.Name
	default:
		return "", nil
	}
	if delegateName == "" || delegateName == callerFd.Name.Name {
		return "", nil
	}
	delegateFd := findFuncDecl(file, delegateName)
	if delegateFd == nil {
		return delegateName, nil
	}
	subst = make(map[string]ast.Expr)
	for i, name := range flattenParamNames(delegateFd.Type.Params) {
		if name == "" || i >= len(call.Args) {
			continue
		}
		subst[name] = call.Args[i]
	}
	return delegateName, subst
}

func (a *Analyzer) extractResponses(file *ast.File, funcName string) map[int]models.Response {
	return a.extractResponsesDepth(file, funcName, nil, 0)
}

func (a *Analyzer) extractResponsesDepth(file *ast.File, funcName string, subst map[string]ast.Expr, depth int) map[int]models.Response {
	fd := findFuncDecl(file, funcName)
	if fd == nil || fd.Body == nil {
		return nil
	}
	recvName := firstParamName(fd)
	if recvName == "" {
		return nil
	}
	varTypes, _, _, _ := collectLocalTypedVars(fd.Body)
	responses := make(map[int]models.Response)

	if a.usesNetHTTPHandlers() {
		a.walkNetHTTPResponses(file, funcName, fd, recvName, varTypes, responses)
		return responses
	}

	var helperCalls []*ast.CallExpr
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if rc, ok := a.recognizeResponseCall(call, recvName, subst); ok {
			a.recordResponseCall(file, funcName, rc, fd.Body, varTypes, responses)
			return true
		}
		if isContextPassthroughCall(call, recvName) {
			helperCalls = append(helperCalls, call)
		}
		return true
	})

	if len(responses) == 0 && depth < 2 {
		for _, call := range helperCalls {
			delegate, callSubst := a.resolveHelperDelegate(file, fd, call)
			if delegate == "" {
				continue
			}
			nested := a.extractResponsesDepth(file, delegate, callSubst, depth+1)
			for status, resp := range nested {
				responses[status] = resp
			}
			if len(responses) > 0 {
				break
			}
		}
	}
	return responses
}
