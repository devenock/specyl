package analyzer

import (
	"go/ast"
	"go/token"
	"reflect"
	"strings"
	"unicode"

	"github.com/devenock/specyl/pkg/models"
)

func (a *Analyzer) collectTypesInFile(filePath string) error {
	fset := token.NewFileSet()
	node, err := a.rootParseFile(fset, filePath, 0)
	if err != nil {
		a.recordParseFailure(filePath, err)
		return nil
	}
	for _, decl := range node.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		if genDecl.Tok == token.CONST || genDecl.Tok == token.VAR {
			a.collectStringConsts(genDecl)
			continue
		}
		if genDecl.Tok != token.TYPE {
			continue
		}
		for _, spec := range genDecl.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}
			structType, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				continue
			}
			name := typeSpec.Name.Name
			schema := a.buildSchemaFromStruct(structType)
			if schema.Type != "" || len(schema.Properties) > 0 {
				a.typeRegistry[name] = schema
				if a.typePackageName == nil {
					a.typePackageName = make(map[string]string)
				}
				a.typePackageName[name] = node.Name.Name
			}
		}
	}
	return nil
}

// buildSchemaFromStruct converts an ast.StructType to a models.Schema (object with properties).
func (a *Analyzer) buildSchemaFromStruct(st *ast.StructType) models.Schema {
	if st.Fields == nil {
		return models.Schema{Type: "object"}
	}
	props := make(map[string]models.Schema)
	var required []string
	var embeds []string
	for _, f := range st.Fields.List {
		if len(f.Names) == 0 {
			embeddedName := embeddedTypeName(f.Type)
			if embeddedName == "" {
				continue
			}
			tags := parseFieldTags(f.Tag)
			if tags.skip {
				continue
			}
			if tags.name != "" {
				props[tags.name] = a.goTypeToSchema(f.Type)
			} else {
				embeds = append(embeds, embeddedName)
			}
			continue
		}

		if !f.Names[0].IsExported() {
			continue
		}
		tags := parseFieldTags(f.Tag)
		if tags.skip {

			continue
		}
		fieldName := f.Names[0].Name
		if tags.name != "" {
			fieldName = tags.name
		}
		fieldSchema := a.goTypeToSchema(f.Type)

		if isPointerType(f.Type) && fieldSchema.Ref == "" {
			fieldSchema.Nullable = true
		}
		props[fieldName] = fieldSchema

		if (tags.required || a.config.RequiredByDefault) && !tags.omitempty {
			required = append(required, fieldName)
		}
	}
	return models.Schema{
		Type:       "object",
		Properties: props,
		Required:   required,
		Embeds:     embeds,
	}
}

type fieldTags struct {
	name      string
	skip      bool
	omitempty bool
	required  bool
}

func parseFieldTags(tag *ast.BasicLit) fieldTags {
	var ft fieldTags
	if tag == nil {
		return ft
	}
	st := reflect.StructTag(strings.Trim(tag.Value, "`"))

	if jsonTag, ok := st.Lookup("json"); ok {
		parts := strings.Split(jsonTag, ",")
		name := parts[0]

		if name == "-" && len(parts) == 1 {
			ft.skip = true
			return ft
		}
		ft.name = name
		for _, opt := range parts[1:] {
			if opt == "omitempty" {
				ft.omitempty = true
			}
		}
	}
	if v, ok := st.Lookup("binding"); ok && tagOptionPresent(v, "required") {
		ft.required = true
	}
	if v, ok := st.Lookup("validate"); ok && tagOptionPresent(v, "required") {
		ft.required = true
	}
	return ft
}

func tagOptionPresent(tagValue, opt string) bool {
	for _, part := range strings.Split(tagValue, ",") {
		if strings.TrimSpace(part) == opt {
			return true
		}
	}
	return false
}

func embeddedTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		if id, ok := t.X.(*ast.Ident); ok {
			return id.Name
		}
	}
	return ""
}

func (a *Analyzer) resolveEmbeddedFields() {
	resolved := make(map[string]bool)
	var flatten func(name string) models.Schema
	flatten = func(name string) models.Schema {
		s, ok := a.typeRegistry[name]
		if !ok || resolved[name] || len(s.Embeds) == 0 {
			return s
		}
		resolved[name] = true // guard against embedding cycles
		if s.Properties == nil {
			s.Properties = make(map[string]models.Schema)
		}
		for _, embedded := range s.Embeds {
			parent := flatten(embedded)
			for propName, propSchema := range parent.Properties {
				if _, exists := s.Properties[propName]; !exists {
					s.Properties[propName] = propSchema
				}
			}
			s.Required = append(s.Required, parent.Required...)
		}
		a.typeRegistry[name] = s
		return s
	}
	for name := range a.typeRegistry {
		flatten(name)
	}
}

var externalTypeSchemas = map[string]models.Schema{
	"time.Time": {Type: "string", Format: "date-time"},

	"time.Duration": {Type: "integer", Format: "int64"},

	"uuid.UUID": {Type: "string", Format: "uuid"},

	"sql.NullString": {Type: "object", Properties: map[string]models.Schema{
		"String": {Type: "string"}, "Valid": {Type: "boolean"},
	}},
	"sql.NullBool": {Type: "object", Properties: map[string]models.Schema{
		"Bool": {Type: "boolean"}, "Valid": {Type: "boolean"},
	}},
	"sql.NullFloat64": {Type: "object", Properties: map[string]models.Schema{
		"Float64": {Type: "number"}, "Valid": {Type: "boolean"},
	}},
	"sql.NullInt64": {Type: "object", Properties: map[string]models.Schema{
		"Int64": {Type: "integer", Format: "int64"}, "Valid": {Type: "boolean"},
	}},
	"sql.NullInt32": {Type: "object", Properties: map[string]models.Schema{
		"Int32": {Type: "integer", Format: "int32"}, "Valid": {Type: "boolean"},
	}},
	"sql.NullInt16": {Type: "object", Properties: map[string]models.Schema{
		"Int16": {Type: "integer"}, "Valid": {Type: "boolean"},
	}},
	"sql.NullByte": {Type: "object", Properties: map[string]models.Schema{
		"Byte": {Type: "integer"}, "Valid": {Type: "boolean"},
	}},
	"sql.NullTime": {Type: "object", Properties: map[string]models.Schema{
		"Time": {Type: "string", Format: "date-time"}, "Valid": {Type: "boolean"},
	}},
}

// goTypeToSchema maps a Go ast.Expr type to an OpenAPI-style Schema.
func (a *Analyzer) goTypeToSchema(expr ast.Expr) models.Schema {
	switch t := expr.(type) {
	case *ast.Ident:
		return a.identToSchema(t.Name)
	case *ast.StarExpr:
		return a.goTypeToSchema(t.X)
	case *ast.ArrayType:
		item := a.goTypeToSchema(t.Elt)
		return models.Schema{Type: "array", Items: &item}
	case *ast.MapType:
		return models.Schema{Type: "object", AdditionalProperties: map[string]interface{}{}}
	case *ast.SelectorExpr:

		if ident, ok := t.X.(*ast.Ident); ok {
			if schema, ok := externalTypeSchemas[ident.Name+"."+t.Sel.Name]; ok {
				return schema
			}
		}
		return models.Schema{Type: "object"}
	case *ast.InterfaceType:
		return models.Schema{Type: "object"}
	default:
		return models.Schema{Type: "object"}
	}
}

// addSchemaAndRefsToModels adds the schema and any referenced types to a.models so OpenAPI components/schemas can resolve $ref.
func (a *Analyzer) addSchemaAndRefsToModels(name string, s models.Schema) {
	a.models[name] = s
	a.addReferencedModels(s)
}

// addReferencedModels adds every type s references, at any depth, to a.models.
func (a *Analyzer) addReferencedModels(s models.Schema) {
	visitSchemaRefs(s, func(refName string) {
		if _, done := a.models[refName]; done {
			return // also stops recursion on self-referential types
		}
		if nested, ok := a.typeRegistry[refName]; ok {
			a.addSchemaAndRefsToModels(refName, nested)
		}
	})
}

// addModelsReferencedByEndpoints ensures every $ref reachable from an endpoint resolves, including refs inside inline schemas (e.g. handler-local structs) that were never added to a.models themselves.
func (a *Analyzer) addModelsReferencedByEndpoints() {
	for _, ep := range a.endpoints {
		for _, p := range ep.Parameters {
			a.addReferencedModels(p.Schema)
		}
		if ep.RequestBody != nil {
			for _, c := range ep.RequestBody.Content {
				a.addReferencedModels(c.Schema)
			}
		}
		for _, resp := range ep.Responses {
			for _, c := range resp.Content {
				a.addReferencedModels(c.Schema)
			}
			for _, h := range resp.Headers {
				a.addReferencedModels(h.Schema)
			}
		}
	}
}

// visitSchemaRefs calls fn with the component name of every $ref in s, recursing into properties and items.
func visitSchemaRefs(s models.Schema, fn func(refName string)) {
	if refName := strings.TrimPrefix(s.Ref, "#/components/schemas/"); refName != "" {
		fn(refName)
	}
	for _, prop := range s.Properties {
		visitSchemaRefs(prop, fn)
	}
	if s.Items != nil {
		visitSchemaRefs(*s.Items, fn)
	}
}

func (a *Analyzer) identToSchema(name string) models.Schema {
	switch name {
	case "string":
		return models.Schema{Type: "string"}
	case "int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16", "uint32", "uint64":
		return models.Schema{Type: "integer", Format: "int64"}
	case "float32", "float64":
		return models.Schema{Type: "number", Format: "double"}
	case "bool":
		return models.Schema{Type: "boolean"}
	case "interface{}":
		return models.Schema{Type: "object"}
	default:
		// Named struct: use ref if in registry, else object
		if _, ok := a.typeRegistry[name]; ok {
			return models.Schema{Ref: "#/components/schemas/" + name}
		}
		return models.Schema{Type: "object"}
	}
}

// getHandlerRequestAndResponseTypes returns the type names for the handler's second param (request body) and first return (response).
func getHandlerRequestAndResponseTypes(file *ast.File, handlerName string) (reqTypeName, respTypeName string) {
	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Name.Name != handlerName || fd.Type.Params == nil {
			continue
		}
		params := fd.Type.Params.List
		if len(params) >= 2 {
			reqTypeName = typeExprToName(params[1].Type)
		}
		if fd.Type.Results != nil && len(fd.Type.Results.List) >= 1 {
			respTypeName = typeExprToName(fd.Type.Results.List[0].Type)
		}
		return reqTypeName, respTypeName
	}
	return "", ""
}

// localTypeName returns the unqualified type name (e.g. "pkg.CreateRequest" -> "CreateRequest").
func localTypeName(name string) string {
	if i := strings.LastIndex(name, "."); i >= 0 {
		return name[i+1:]
	}
	return name
}

func typeExprToName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return typeExprToName(t.X)
	case *ast.SelectorExpr:
		if id, ok := t.X.(*ast.Ident); ok {
			return id.Name + "." + t.Sel.Name
		}
		return ""
	default:
		return ""
	}
}

func isPointerType(expr ast.Expr) bool {
	_, ok := expr.(*ast.StarExpr)
	return ok
}

// looksLikeHandlerName returns true if s looks like a Go handler name (CamelCase, no spaces, no slash).
func looksLikeHandlerName(s string) bool {
	if s == "" || strings.Contains(s, " ") || strings.Contains(s, "/") {
		return false
	}
	// At least one lower and one upper for CamelCase, or single word
	hasUpper := false
	hasLower := false
	for _, r := range s {
		if unicode.IsUpper(r) {
			hasUpper = true
		}
		if unicode.IsLower(r) {
			hasLower = true
		}
	}
	return hasUpper && (hasLower || len(s) <= 2)
}

// humanizeHandlerName turns a handler name like "CreateProduct" into "Create product".
func humanizeHandlerName(name string) string {
	if name == "" {
		return ""
	}
	var b strings.Builder
	for i, r := range name {
		if i > 0 && unicode.IsUpper(r) {
			b.WriteByte(' ')
			b.WriteRune(unicode.ToLower(r))
		} else {
			b.WriteRune(r)
		}
	}
	s := b.String()
	if s == "" {
		return s
	}
	runes := []rune(s)
	runes[0] = unicode.ToUpper(runes[0])
	return string(runes)
}
