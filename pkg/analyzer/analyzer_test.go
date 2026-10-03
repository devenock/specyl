package analyzer

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/devenock/specyl/pkg/config"
	"github.com/devenock/specyl/pkg/models"
)

func writeProject(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, content := range files {
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func analyze(t *testing.T, dir, framework string) *models.APISpec {
	t.Helper()
	cfg := &config.Config{
		ProjectPath: dir,
		Framework:   framework,
		DocType:     "swagger",
		Title:       "Test API",
		Version:     "1.0.0",
	}
	spec, err := NewAnalyzer(cfg).Analyze()
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	return spec
}

func findEndpoint(t *testing.T, spec *models.APISpec, method, path string) models.Endpoint {
	t.Helper()
	for _, e := range spec.Endpoints {
		if e.Method == method && e.Path == path {
			return e
		}
	}
	var got []string
	for _, e := range spec.Endpoints {
		got = append(got, e.Method+" "+e.Path)
	}
	t.Fatalf("endpoint %s %s not found; got %v", method, path, got)
	return models.Endpoint{}
}

func TestAnalyze_Gin_GroupsParamsBindingAndAuth(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"go.mod": "module example.com/api\n\ngo 1.24\n",
		"main.go": `package main

import "github.com/gin-gonic/gin"

type CreateUserRequest struct {
	Name string ` + "`json:\"name\"`" + `
}

func main() {
	r := gin.Default()
	v1 := r.Group("/api/v1")
	v1.GET("/users/:id", GetUser)
	v1.POST("/users", CreateUser)

	admin := v1.Group("/admin", AuthMiddleware())
	admin.GET("/stats", GetStats)
}

func GetUser(c *gin.Context) {}

// CreateUser creates a new user.
func CreateUser(c *gin.Context) {
	var req CreateUserRequest
	c.ShouldBindJSON(&req)
}

func GetStats(c *gin.Context) {}
func AuthMiddleware() gin.HandlerFunc { return nil }
`,
	})

	spec := analyze(t, dir, "gin")

	get := findEndpoint(t, spec, "GET", "/api/v1/users/{id}")
	if len(get.Parameters) != 1 || get.Parameters[0].Name != "id" || get.Parameters[0].In != "path" {
		t.Errorf("GetUser params = %+v, want a single path param \"id\"", get.Parameters)
	}
	if len(get.Security) != 0 {
		t.Errorf("GetUser is not behind auth middleware, want no Security, got %v", get.Security)
	}

	create := findEndpoint(t, spec, "POST", "/api/v1/users")
	if create.RequestBody == nil {
		t.Fatal("CreateUser: expected a request body inferred from ShouldBindJSON(&req)")
	}
	if create.RequestTypeName != "CreateUserRequest" {
		t.Errorf("RequestTypeName = %q, want CreateUserRequest", create.RequestTypeName)
	}
	if !strings.Contains(create.Description, "creates a new user") {
		t.Errorf("Description = %q, want it to include the doc comment", create.Description)
	}

	stats := findEndpoint(t, spec, "GET", "/api/v1/admin/stats")
	if len(stats.Security) == 0 {
		t.Error("GetStats is registered on a group behind AuthMiddleware(), want Security to be set")
	}
}

func TestAnalyze_Gin_GroupPrefixAndPathFromNamedConstant(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"go.mod": "module example.com/api\n\ngo 1.24\n",
		"main.go": `package main

import "github.com/gin-gonic/gin"

const apiV1Prefix = "/api/v1"
const usersPath = "/users"

func main() {
	r := gin.Default()
	v1 := r.Group(apiV1Prefix)
	v1.GET(usersPath, ListUsers)
}

func ListUsers(c *gin.Context) {}
`,
	})

	spec := analyze(t, dir, "gin")

	findEndpoint(t, spec, "GET", "/api/v1/users")
}

func TestAnalyze_ServerURL_DetectedFromListenCall(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"go.mod": "module example.com/api\n\ngo 1.24\n",
		"main.go": `package main

import "github.com/gin-gonic/gin"

func main() {
	r := gin.Default()
	r.GET("/ping", Ping)
	r.Run(":9091")
}

func Ping(c *gin.Context) {}
`,
	})

	spec := analyze(t, dir, "gin")

	if len(spec.Servers) != 1 || spec.Servers[0].URL != "http://localhost:9091" {
		t.Errorf("Servers = %+v, want a single server at http://localhost:9091", spec.Servers)
	}
}

func TestAnalyze_ServerURL_FallsBackToEnvWhenPortIsNotALiteral(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"go.mod": "module example.com/api\n\ngo 1.24\n",
		".env":   "PORT=9999\n",
		"main.go": `package main

import (
	"net/http"
	"os"
)

func main() {
	http.HandleFunc("/ping", Ping)
	http.ListenAndServe(":"+os.Getenv("PORT"), nil)
}

func Ping(w http.ResponseWriter, r *http.Request) {}
`,
	})

	spec := analyze(t, dir, "")

	if len(spec.Servers) != 1 || spec.Servers[0].URL != "http://localhost:9999" {
		t.Errorf("Servers = %+v, want a single server at http://localhost:9999 (from .env)", spec.Servers)
	}
}

func TestAnalyzer_DetectedPort_MatchesEnvFallback(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"go.mod": "module example.com/api\n\ngo 1.24\n",
		".env":   "PORT=9999\n",
		"main.go": `package main

import (
	"net/http"
	"os"
)

func main() {
	http.HandleFunc("/ping", Ping)
	http.ListenAndServe(":"+os.Getenv("PORT"), nil)
}

func Ping(w http.ResponseWriter, r *http.Request) {}
`,
	})

	cfg := &config.Config{ProjectPath: dir, DocType: "swagger", Title: "Test API", Version: "1.0.0"}
	a := NewAnalyzer(cfg)
	spec, err := a.Analyze()
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	if len(spec.Servers) != 1 || spec.Servers[0].URL != "http://localhost:9999" {
		t.Fatalf("Servers = %+v, want a single server at http://localhost:9999 (from .env)", spec.Servers)
	}
	if got := a.DetectedPort(); got != "9999" {
		t.Errorf("DetectedPort() = %q, want %q to match Servers[0].URL", got, "9999")
	}
}

func TestAnalyzer_DetectedPort_EmptyWhenServersConfigured(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"go.mod":  "module example.com/api\n\ngo 1.24\n",
		"main.go": "package main\n\nfunc main() {}\n",
	})

	cfg := &config.Config{
		ProjectPath: dir, DocType: "swagger", Title: "Test API", Version: "1.0.0",
		Servers: []config.ServerConfig{{URL: "https://api.example.com"}},
	}
	a := NewAnalyzer(cfg)
	if _, err := a.Analyze(); err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	if got := a.DetectedPort(); got != "" {
		t.Errorf("DetectedPort() = %q, want \"\" when servers are user-configured", got)
	}
}

func TestAnalyze_Gin_EmbeddedFieldsPromotedIntoSchema(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"go.mod": "module example.com/api\n\ngo 1.24\n",
		"main.go": `package main

import "github.com/gin-gonic/gin"

type BaseModel struct {
	ID uint ` + "`json:\"id\"`" + `
}

type Product struct {
	BaseModel
	Name string ` + "`json:\"name\"`" + `
}

func main() {
	r := gin.Default()
	r.POST("/products", CreateProduct)
}

func CreateProduct(c *gin.Context) {
	var p Product
	c.ShouldBindJSON(&p)
}
`,
	})

	spec := analyze(t, dir, "gin")
	schema, ok := spec.Models["Product"]
	if !ok {
		t.Fatal("expected Product schema in spec.Models")
	}
	if _, ok := schema.Properties["id"]; !ok {
		t.Errorf("Product.Properties = %v, want promoted embedded field \"id\"", schema.Properties)
	}
	if _, ok := schema.Properties["name"]; !ok {
		t.Errorf("Product.Properties = %v, want \"name\"", schema.Properties)
	}
}

func TestAnalyze_ExternalTypeSchemas(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"go.mod": "module example.com/api\n\ngo 1.24\n",
		"main.go": `package main

import (
	"database/sql"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type Account struct {
	ID        uuid.UUID      ` + "`json:\"id\"`" + `
	CreatedAt time.Time      ` + "`json:\"created_at\"`" + `
	Timeout   time.Duration  ` + "`json:\"timeout\"`" + `
	Nickname  sql.NullString ` + "`json:\"nickname\"`" + `
}

func CreateAccount(c *gin.Context) {
	var a Account
	c.ShouldBindJSON(&a)
	c.JSON(201, a)
}

func main() {
	r := gin.Default()
	r.POST("/accounts", CreateAccount)
	r.Run()
}
`,
	})

	spec := analyze(t, dir, "gin")
	schema, ok := spec.Models["Account"]
	if !ok {
		t.Fatal("expected Account schema in spec.Models")
	}

	id := schema.Properties["id"]
	if id.Type != "string" || id.Format != "uuid" {
		t.Errorf("id (uuid.UUID) = %+v, want {Type: string, Format: uuid}", id)
	}
	createdAt := schema.Properties["created_at"]
	if createdAt.Type != "string" || createdAt.Format != "date-time" {
		t.Errorf("created_at (time.Time) = %+v, want {Type: string, Format: date-time}", createdAt)
	}
	timeout := schema.Properties["timeout"]
	if timeout.Type != "integer" || timeout.Format != "int64" {
		t.Errorf("timeout (time.Duration) = %+v, want {Type: integer, Format: int64}", timeout)
	}
	nickname := schema.Properties["nickname"]
	if nickname.Type != "object" {
		t.Fatalf("nickname (sql.NullString) = %+v, want Type: object", nickname)
	}
	if s, ok := nickname.Properties["String"]; !ok || s.Type != "string" {
		t.Errorf("nickname.String = %+v, want {Type: string}", s)
	}
	if v, ok := nickname.Properties["Valid"]; !ok || v.Type != "boolean" {
		t.Errorf("nickname.Valid = %+v, want {Type: boolean}", v)
	}
}

func TestAnalyze_Gin_JSONTagSemantics(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"go.mod": "module example.com/api\n\ngo 1.24\n",
		"main.go": `package main

import "github.com/gin-gonic/gin"

type Account struct {
	ID           string  ` + "`json:\"id\"`" + `
	Email        string  ` + "`json:\"email\" binding:\"required\"`" + `
	Nickname     string  ` + "`json:\"nickname,omitempty\"`" + `
	PasswordHash string  ` + "`json:\"-\"`" + `
	APIToken     string
	internalFlag bool
	Balance      *float64 ` + "`json:\"balance\"`" + `
}

func CreateAccount(c *gin.Context) {
	var a Account
	c.ShouldBindJSON(&a)
	c.JSON(201, a)
}

func main() {
	r := gin.Default()
	r.POST("/accounts", CreateAccount)
	r.Run()
}
`,
	})

	spec := analyze(t, dir, "gin")
	schema, ok := spec.Models["Account"]
	if !ok {
		t.Fatal("expected Account schema in spec.Models")
	}

	if _, ok := schema.Properties["PasswordHash"]; ok {
		t.Error(`json:"-" field PasswordHash must not appear in the schema (secret-bearing field leak)`)
	}
	if _, ok := schema.Properties["internalFlag"]; ok {
		t.Error("unexported field internalFlag must not appear in the schema (encoding/json never marshals it)")
	}

	if _, ok := schema.Properties["APIToken"]; !ok {
		t.Error("APIToken has no exclusion tag, so encoding/json would marshal it — it should still appear in the schema")
	}
	for _, name := range []string{"id", "email", "nickname", "balance"} {
		if _, ok := schema.Properties[name]; !ok {
			t.Errorf("expected tagged property %q in schema, got %v", name, schema.Properties)
		}
	}

	wantRequired := []string{"email"}
	if !slicesEqualUnordered(schema.Required, wantRequired) {
		t.Errorf("Required = %v, want %v (only binding:\"required\" fields, regardless of pointer-ness)", schema.Required, wantRequired)
	}

	balance := schema.Properties["balance"]
	if !balance.Nullable {
		t.Error("Balance is a pointer field, want Nullable=true (pointer-ness means nullable, not required)")
	}

	create := findEndpoint(t, spec, "POST", "/accounts")
	if create.RequestTypeName != "Account" {
		t.Errorf("RequestTypeName = %q, want Account", create.RequestTypeName)
	}
}

func TestAnalyze_RequiredByDefault(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"go.mod": "module example.com/api\n\ngo 1.24\n",
		"main.go": `package main

import "github.com/gin-gonic/gin"

type Account struct {
	ID       string ` + "`json:\"id\"`" + `
	Email    string ` + "`json:\"email\" binding:\"required\"`" + `
	Nickname string ` + "`json:\"nickname,omitempty\"`" + `
}

func CreateAccount(c *gin.Context) {
	var a Account
	c.ShouldBindJSON(&a)
	c.JSON(201, a)
}

func main() {
	r := gin.Default()
	r.POST("/accounts", CreateAccount)
	r.Run()
}
`,
	})

	cfg := &config.Config{
		ProjectPath:       dir,
		Framework:         "gin",
		DocType:           "swagger",
		Title:             "Test API",
		Version:           "1.0.0",
		RequiredByDefault: true,
	}
	spec, err := NewAnalyzer(cfg).Analyze()
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	schema, ok := spec.Models["Account"]
	if !ok {
		t.Fatal("expected Account schema in spec.Models")
	}
	wantRequired := []string{"id", "email"}
	if !slicesEqualUnordered(schema.Required, wantRequired) {
		t.Errorf("Required = %v, want %v (every field but the omitempty one)", schema.Required, wantRequired)
	}
}

func TestAnalyze_JSONTag_DashCommaIsALiteralFieldName(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"go.mod": "module example.com/api\n\ngo 1.24\n",
		"main.go": `package main

import "github.com/gin-gonic/gin"

type Weird struct {
	Dash string ` + "`json:\"-,\"`" + `
}

func Create(c *gin.Context) {
	var w Weird
	c.ShouldBindJSON(&w)
}

func main() {
	r := gin.Default()
	r.POST("/weird", Create)
}
`,
	})

	spec := analyze(t, dir, "gin")
	schema, ok := spec.Models["Weird"]
	if !ok {
		t.Fatal("expected Weird schema in spec.Models")
	}
	if _, ok := schema.Properties["-"]; !ok {
		t.Errorf(`json:"-," should marshal under the literal name "-", got properties %v`, schema.Properties)
	}
}

func slicesEqualUnordered(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := make(map[string]bool, len(want))
	for _, w := range want {
		seen[w] = true
	}
	for _, g := range got {
		if !seen[g] {
			return false
		}
	}
	return true
}

func TestAnalyze_Gin_ResponseInference_EdgeStatusCodes(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"go.mod": "module example.com/api\n\ngo 1.24\n",
		"handlers/handlers.go": `package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type CreateUserRequest struct {
	Email string ` + "`json:\"email\"`" + `
}

type UserResponse struct {
	ID    string ` + "`json:\"id\"`" + `
	Email string ` + "`json:\"email\"`" + `
}

type ErrorResponse struct {
	Message string ` + "`json:\"message\"`" + `
	Code    string ` + "`json:\"code\"`" + `
}

func CreateUser(c *gin.Context) {
	var req CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Message: "invalid", Code: "bad_request"})
		return
	}
	c.JSON(http.StatusCreated, UserResponse{ID: "1", Email: req.Email})
}

func DeleteUser(c *gin.Context) {
	c.Status(http.StatusNoContent)
}
`,
		"main.go": `package main

import (
	"example.com/api/handlers"
	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()
	r.POST("/users", handlers.CreateUser)
	r.DELETE("/users/:id", handlers.DeleteUser)
}
`,
	})

	spec := analyze(t, dir, "gin")

	create := findEndpoint(t, spec, "POST", "/users")
	created, ok := create.Responses[201]
	if !ok {
		t.Fatalf("CreateUser: expected a 201 response, got %v", create.Responses)
	}
	createdSchema := created.Content["application/json"].Schema
	if _, ok := createdSchema.Properties["id"]; !ok {
		t.Errorf("201 response schema = %v, want UserResponse properties (id, email)", createdSchema)
	}
	badReq, ok := create.Responses[400]
	if !ok {
		t.Fatalf("CreateUser: expected a 400 response, got %v", create.Responses)
	}
	badReqSchema := badReq.Content["application/json"].Schema
	if _, ok := badReqSchema.Properties["message"]; !ok {
		t.Errorf("400 response schema = %v, want ErrorResponse properties (message, code)", badReqSchema)
	}
	if _, ok := spec.Models["UserResponse"]; !ok {
		t.Error("expected UserResponse registered in spec.Models")
	}
	if _, ok := spec.Models["ErrorResponse"]; !ok {
		t.Error("expected ErrorResponse registered in spec.Models")
	}

	del := findEndpoint(t, spec, "DELETE", "/users/{id}")
	noContent, ok := del.Responses[204]
	if !ok {
		t.Fatalf("DeleteUser: expected a 204 response, got %v", del.Responses)
	}
	if len(noContent.Content) != 0 {
		t.Errorf("204 response should have no content block, got %v", noContent.Content)
	}
	if _, has200 := del.Responses[200]; has200 {
		t.Error("DeleteUser must not also get a fabricated 200 — it never returns one")
	}
}

func TestAnalyze_Echo_ResponseInference(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"go.mod": "module example.com/api\n\ngo 1.24\n",
		"main.go": `package main

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

type PingResponse struct {
	Status string ` + "`json:\"status\"`" + `
}

func Ping(c echo.Context) error {
	return c.JSON(http.StatusOK, PingResponse{Status: "ok"})
}

func Delete(c echo.Context) error {
	return c.NoContent(http.StatusNoContent)
}

func main() {
	e := echo.New()
	e.GET("/ping", Ping)
	e.DELETE("/items/:id", Delete)
}
`,
	})

	spec := analyze(t, dir, "echo")
	ping := findEndpoint(t, spec, "GET", "/ping")
	resp, ok := ping.Responses[200]
	if !ok || resp.Content["application/json"].Schema.Properties["status"].Type != "string" {
		t.Errorf("Ping: Responses = %v, want 200 with PingResponse schema", ping.Responses)
	}

	del := findEndpoint(t, spec, "DELETE", "/items/{id}")
	if noContent, ok := del.Responses[204]; !ok || len(noContent.Content) != 0 {
		t.Errorf("Delete: Responses = %v, want bodyless 204", del.Responses)
	}
}

func TestAnalyze_Fiber_ResponseInference_DirectAndChained(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"go.mod": "module example.com/api\n\ngo 1.24\n",
		"main.go": `package main

import "github.com/gofiber/fiber/v2"

type ItemResponse struct {
	Name string ` + "`json:\"name\"`" + `
}

func Get(c *fiber.Ctx) error {
	return c.JSON(ItemResponse{Name: "widget"})
}

func Create(c *fiber.Ctx) error {
	return c.Status(fiber.StatusCreated).JSON(ItemResponse{Name: "new widget"})
}

func main() {
	app := fiber.New()
	app.Get("/items", Get)
	app.Post("/items", Create)
}
`,
	})

	spec := analyze(t, dir, "fiber")
	get := findEndpoint(t, spec, "GET", "/items")
	if resp, ok := get.Responses[200]; !ok || resp.Content["application/json"].Schema.Properties["name"].Type != "string" {
		t.Errorf("Get: Responses = %v, want 200 with ItemResponse schema (default status)", get.Responses)
	}

	create := findEndpoint(t, spec, "POST", "/items")
	if resp, ok := create.Responses[201]; !ok || resp.Content["application/json"].Schema.Properties["name"].Type != "string" {
		t.Errorf("Create: Responses = %v, want 201 with ItemResponse schema (chained .Status().JSON())", create.Responses)
	}
}

func TestAnalyze_Gorilla_ResponseInference_BranchScoped(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"go.mod": "module example.com/api\n\ngo 1.24\n",
		"main.go": `package main

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
)

type OKResponse struct {
	Result string ` + "`json:\"result\"`" + `
}

type FailResponse struct {
	Error string ` + "`json:\"error\"`" + `
}

func Handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("fail") != "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(FailResponse{Error: "bad input"})
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(OKResponse{Result: "done"})
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/handle", Handle).Methods("POST")
}
`,
	})

	spec := analyze(t, dir, "gorilla")
	ep := findEndpoint(t, spec, "POST", "/handle")

	ok, hasOK := ep.Responses[200]
	if !hasOK || ok.Content["application/json"].Schema.Properties["result"].Type != "string" {
		t.Errorf("Responses[200] = %v, want OKResponse schema", ep.Responses[200])
	}
	bad, hasBad := ep.Responses[400]
	if !hasBad || bad.Content["application/json"].Schema.Properties["error"].Type != "string" {
		t.Errorf("Responses[400] = %v, want FailResponse schema (from the other branch, not conflated with 200)", ep.Responses[400])
	}
}

func TestAnalyze_Gin_ResponseInference_HelperDelegation(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"go.mod": "module example.com/api\n\ngo 1.24\n",
		"main.go": `package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func respondError(c *gin.Context, status int, msg string) {
	c.JSON(status, gin.H{"error": msg})
}

func GetThing(c *gin.Context) {
	respondError(c, http.StatusNotFound, "not found")
}

func main() {
	r := gin.Default()
	r.GET("/things/:id", GetThing)
}
`,
	})

	spec := analyze(t, dir, "gin")
	ep := findEndpoint(t, spec, "GET", "/things/{id}")
	resp, ok := ep.Responses[404]
	if !ok {
		t.Fatalf("GetThing: Responses = %v, want 404 resolved through respondError", ep.Responses)
	}
	if _, ok := resp.Content["application/json"].Schema.Properties["error"]; !ok {
		t.Errorf("404 response schema = %v, want an \"error\" property inferred from gin.H{\"error\": msg}", resp.Content["application/json"].Schema)
	}
}

func TestAnalyze_Gin_ResponseInference_PlaceholderIsLabeled(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"go.mod": "module example.com/api\n\ngo 1.24\n",
		"main.go": `package main

import "github.com/gin-gonic/gin"

func Mystery(c *gin.Context) {
	someUnrecognizedSink(c)
}

func someUnrecognizedSink(c *gin.Context) {}

func main() {
	r := gin.Default()
	r.GET("/mystery", Mystery)
}
`,
	})

	spec := analyze(t, dir, "gin")
	ep := findEndpoint(t, spec, "GET", "/mystery")
	if len(ep.Responses) != 1 {
		t.Fatalf("Responses = %v, want exactly one placeholder entry", ep.Responses)
	}
	resp, ok := ep.Responses[200]
	if !ok || resp.Description != "Response shape could not be inferred" {
		t.Errorf("Responses[200] = %+v, want the labeled placeholder", resp)
	}
}

func TestAnalyze_Gin_AddressTakenFallback_ExcludesActualResponseVar(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"go.mod": "module example.com/api\n\ngo 1.24\n",
		"main.go": `package main

import "github.com/gin-gonic/gin"

type Result struct {
	OK bool ` + "`json:\"ok\"`" + `
}

type Payload struct {
	Name string ` + "`json:\"name\"`" + `
}

func fillResult(out *Result) { out.OK = true }
func customBind(c *gin.Context, v *Payload) error { return nil }

func Handler(c *gin.Context) {
	var out Result
	fillResult(&out)

	var p Payload
	customBind(c, &p)

	c.JSON(200, out)
}

func main() {
	r := gin.Default()
	r.POST("/handle", Handler)
}
`,
	})

	spec := analyze(t, dir, "gin")
	ep := findEndpoint(t, spec, "POST", "/handle")
	if ep.RequestBody == nil {
		t.Fatal("expected a request body to be inferred")
	}
	if ep.RequestTypeName != "Payload" {
		t.Errorf("RequestTypeName = %q, want Payload (Result is the response, declared and address-taken first)", ep.RequestTypeName)
	}
}

func TestAnalyze_AuthMiddleware_ConfiguredListOverridesHeuristic(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"go.mod": "module example.com/api\n\ngo 1.24\n",
		"main.go": `package main

import "github.com/gin-gonic/gin"

func main() {
	r := gin.Default()

	authored := r.Group("/authored", AuthorMiddleware())
	authored.GET("/posts", ListPosts)

	protected := r.Group("/protected", requireSession)
	protected.GET("/dashboard", Dashboard)
}

func ListPosts(c *gin.Context) {}
func Dashboard(c *gin.Context)  {}
func AuthorMiddleware() gin.HandlerFunc { return nil }
func requireSession(c *gin.Context)     {}
`,
	})

	cfg := &config.Config{
		ProjectPath: dir, Framework: "gin", DocType: "swagger", Title: "T", Version: "1.0.0",
		AuthMiddleware: []string{"requireSession"},
	}
	spec, err := NewAnalyzer(cfg).Analyze()
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	posts := findEndpoint(t, spec, "GET", "/authored/posts")
	if len(posts.Security) != 0 {
		t.Errorf("ListPosts uses AuthorMiddleware (not in the configured list), want no Security, got %v", posts.Security)
	}

	dashboard := findEndpoint(t, spec, "GET", "/protected/dashboard")
	if len(dashboard.Security) == 0 {
		t.Error("Dashboard uses requireSession (in the configured list), want Security to be set")
	}
}

func TestAnalyze_VerboseMode_ReportsHeuristicMatches(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"go.mod": "module example.com/api\n\ngo 1.24\n",
		"main.go": `package main

import "github.com/gin-gonic/gin"

func main() {
	r := gin.Default()
	admin := r.Group("/admin", JWTAuth())
	admin.GET("/stats", Stats)
}

func Stats(c *gin.Context) {}
func JWTAuth() gin.HandlerFunc { return nil }
`,
	})

	cfg := &config.Config{ProjectPath: dir, Framework: "gin", DocType: "swagger", Title: "T", Version: "1.0.0", Verbose: true}
	a := NewAnalyzer(cfg)
	if _, err := a.Analyze(); err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if !slicesEqualUnordered(a.AuthMiddlewareMatches(), []string{"JWTAuth"}) {
		t.Errorf("AuthMiddlewareMatches() = %v, want [JWTAuth]", a.AuthMiddlewareMatches())
	}

	cfg2 := &config.Config{ProjectPath: dir, Framework: "gin", DocType: "swagger", Title: "T", Version: "1.0.0", Verbose: false}
	a2 := NewAnalyzer(cfg2)
	if _, err := a2.Analyze(); err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(a2.AuthMiddlewareMatches()) != 0 {
		t.Errorf("AuthMiddlewareMatches() = %v, want empty when Verbose is false (not tracked)", a2.AuthMiddlewareMatches())
	}
}

func TestAnalyze_Fiber_GroupAndBodyParser(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"go.mod": "module example.com/api\n\ngo 1.24\n",
		"main.go": `package main

import "github.com/gofiber/fiber/v2"

type LoginRequest struct {
	Email string ` + "`json:\"email\"`" + `
}

func main() {
	app := fiber.New()
	api := app.Group("/api")
	api.Post("/login", Login)
}

func Login(c *fiber.Ctx) error {
	var req LoginRequest
	return c.BodyParser(&req)
}
`,
	})

	spec := analyze(t, dir, "fiber")
	ep := findEndpoint(t, spec, "POST", "/api/login")
	if ep.RequestBody == nil || ep.RequestTypeName != "LoginRequest" {
		t.Errorf("Login: RequestTypeName = %q, want LoginRequest (from BodyParser)", ep.RequestTypeName)
	}
}

func TestAnalyze_Gorilla_SubrouterMethodsAndAuth(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"go.mod": "module example.com/api\n\ngo 1.24\n",
		"main.go": `package main

import (
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/health", HealthCheck)

	api := r.PathPrefix("/api/v1").Subrouter()
	api.Use(AuthMiddleware)
	api.HandleFunc("/users", ListUsers).Methods("GET")
	api.HandleFunc("/users", CreateUser).Methods(http.MethodPost)
}

func HealthCheck(w http.ResponseWriter, r *http.Request) {}
func ListUsers(w http.ResponseWriter, r *http.Request)   {}
func CreateUser(w http.ResponseWriter, r *http.Request)  {}
func AuthMiddleware(next http.Handler) http.Handler      { return next }
`,
	})

	spec := analyze(t, dir, "gorilla")

	health := findEndpoint(t, spec, "GET", "/health")
	if len(health.Security) != 0 {
		t.Errorf("HealthCheck has no auth middleware, want no Security, got %v", health.Security)
	}

	list := findEndpoint(t, spec, "GET", "/api/v1/users")
	if len(list.Security) == 0 {
		t.Error("ListUsers is under a subrouter with .Use(AuthMiddleware), want Security to be set")
	}

	create := findEndpoint(t, spec, "POST", "/api/v1/users")
	if len(create.Security) == 0 {
		t.Error("CreateUser (.Methods(http.MethodPost)) should resolve to POST and inherit auth")
	}
}

func TestAnalyze_Chi_NestedRoutesAndScopedAuth(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"go.mod": "module example.com/api\n\ngo 1.24\n",
		"main.go": `package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

func main() {
	r := chi.NewRouter()
	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/ping", Ping)

		r.Route("/admin", func(r chi.Router) {
			r.Use(AuthMiddleware)
			r.Get("/stats", Stats)
		})
	})
}

func Ping(w http.ResponseWriter, r *http.Request)  {}
func Stats(w http.ResponseWriter, r *http.Request) {}
func AuthMiddleware(next http.Handler) http.Handler { return next }
`,
	})

	spec := analyze(t, dir, "chi")

	ping := findEndpoint(t, spec, "GET", "/api/v1/ping")
	if len(ping.Security) != 0 {
		t.Errorf("Ping is outside the /admin scope, want no Security, got %v", ping.Security)
	}

	stats := findEndpoint(t, spec, "GET", "/api/v1/admin/stats")
	if len(stats.Security) == 0 {
		t.Error("Stats is inside the /admin scope with .Use(AuthMiddleware), want Security to be set")
	}
}

func TestAnalyze_Chi_ResponseInference(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"go.mod": "module example.com/api\n\ngo 1.24\n",
		"main.go": `package main

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
)

type Widget struct {
	Name string ` + "`json:\"name\"`" + `
}

func GetWidget(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(Widget{Name: "gizmo"})
}

func main() {
	r := chi.NewRouter()
	r.Get("/widgets", GetWidget)
}
`,
	})

	spec := analyze(t, dir, "chi")
	ep := findEndpoint(t, spec, "GET", "/widgets")
	resp, ok := ep.Responses[200]
	if !ok {
		t.Fatalf("GetWidget: Responses = %v, want 200 (net/http default status when WriteHeader is never called)", ep.Responses)
	}
	if resp.Content["application/json"].Schema.Properties["name"].Type != "string" {
		t.Errorf("200 response schema = %v, want Widget properties", resp.Content["application/json"].Schema)
	}
}

func TestAnalyze_Gin_ResponseInference_MapLiteralBody(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"go.mod": "module example.com/api\n\ngo 1.24\n",
		"main.go": `package main

import "github.com/gin-gonic/gin"

func Health(c *gin.Context) {
	c.JSON(200, gin.H{"status": "ok", "version": "1.0"})
}

func main() {
	r := gin.Default()
	r.GET("/health", Health)
}
`,
	})

	spec := analyze(t, dir, "gin")
	ep := findEndpoint(t, spec, "GET", "/health")
	resp, ok := ep.Responses[200]
	if !ok {
		t.Fatalf("Health: Responses = %v, want 200", ep.Responses)
	}
	schema := resp.Content["application/json"].Schema
	for _, key := range []string{"status", "version"} {
		if prop, ok := schema.Properties[key]; !ok || prop.Type != "string" {
			t.Errorf("schema.Properties[%q] = %v, want a string placeholder inferred from the gin.H key", key, prop)
		}
	}
}

func TestAnalyze_Gin_ResponseInference_CallExprBody(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"go.mod": "module example.com/api\n\ngo 1.24\n",
		"main.go": `package main

import "github.com/gin-gonic/gin"

type UserResponse struct {
	ID string ` + "`json:\"id\"`" + `
}

func buildResponse(id string) UserResponse {
	return UserResponse{ID: id}
}

func GetUser(c *gin.Context) {
	c.JSON(200, buildResponse("1"))
}

func main() {
	r := gin.Default()
	r.GET("/users/:id", GetUser)
}
`,
	})

	spec := analyze(t, dir, "gin")
	ep := findEndpoint(t, spec, "GET", "/users/{id}")
	resp, ok := ep.Responses[200]
	if !ok {
		t.Fatalf("GetUser: Responses = %v, want 200", ep.Responses)
	}
	if _, ok := resp.Content["application/json"].Schema.Properties["id"]; !ok {
		t.Errorf("schema = %v, want UserResponse's \"id\" property resolved from buildResponse's return type", resp.Content["application/json"].Schema)
	}
}

func TestAnalyze_RecordsParseFailureDiagnostic(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"go.mod": "module example.com/api\n\ngo 1.24\n",
		"broken.go": `package main

func broken( {{{ this is not valid go syntax
`,
		"main.go": `package main

import "github.com/gin-gonic/gin"

func Health(c *gin.Context) {
	c.JSON(200, gin.H{"status": "ok"})
}

func main() {
	r := gin.Default()
	r.GET("/health", Health)
}
`,
	})

	cfg := &config.Config{ProjectPath: dir, Framework: "gin", DocType: "swagger", Title: "T", Version: "1.0.0"}
	a := NewAnalyzer(cfg)
	spec, err := a.Analyze()
	if err != nil {
		t.Fatalf("Analyze: %v (a broken file must not fail the whole run)", err)
	}
	findEndpoint(t, spec, "GET", "/health")

	diags := a.Diagnostics()
	if len(diags) != 1 {
		t.Fatalf("Diagnostics() = %v, want exactly one entry for broken.go", diags)
	}
	if filepath.Base(diags[0].File) != "broken.go" {
		t.Errorf("Diagnostics()[0].File = %q, want broken.go", diags[0].File)
	}
	if diags[0].Err == nil {
		t.Error("Diagnostics()[0].Err = nil, want the parse error")
	}
}

func TestAnalyze_SkipsSymlinkedGoFiles(t *testing.T) {
	outsideDir := t.TempDir()
	secretFile := filepath.Join(outsideDir, "secret.go")
	if err := os.WriteFile(secretFile, []byte(`package outside

import "net/http"

func SecretHandler(w http.ResponseWriter, r *http.Request) {}

func init() {
	http.HandleFunc("/should-not-appear", SecretHandler)
}
`), 0o644); err != nil {
		t.Fatal(err)
	}

	dir := writeProject(t, map[string]string{
		"go.mod": "module example.com/api\n\ngo 1.24\n",
		"main.go": `package main

import "net/http"

func Health(w http.ResponseWriter, r *http.Request) {}

func main() {
	http.HandleFunc("/health", Health)
}
`,
	})
	if err := os.Symlink(secretFile, filepath.Join(dir, "evil.go")); err != nil {
		t.Skipf("symlinks not supported on this platform: %v", err)
	}

	// No known framework markers in go.mod -> generic net/http route parsing.
	spec := analyze(t, dir, "")

	for _, ep := range spec.Endpoints {
		if ep.Path == "/should-not-appear" {
			t.Fatal("a route registered in a symlinked .go file must not be included in the analysis")
		}
	}
	findEndpoint(t, spec, "GET", "/health")
}

func TestDetectFramework(t *testing.T) {
	tests := []struct {
		require string
		want    string
	}{
		{"require github.com/gin-gonic/gin v1.9.0", "gin"},
		{"require github.com/labstack/echo/v4 v4.11.0", "echo"},
		{"require github.com/gofiber/fiber/v2 v2.50.0", "fiber"},
		{"require github.com/gorilla/mux v1.8.0", "gorilla"},
		{"require github.com/go-chi/chi/v5 v5.0.0", "chi"},
		{"require github.com/spf13/cobra v1.8.0", ""},
	}
	for _, tt := range tests {
		dir := t.TempDir()
		content := "module example.com/x\n\ngo 1.24\n\n" + tt.require + "\n"
		if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := DetectFramework(dir); got != tt.want {
			t.Errorf("DetectFramework(%q) = %q, want %q", tt.require, got, tt.want)
		}
	}
}

func TestDetectFramework_AmbiguousReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	content := "module example.com/x\n\ngo 1.24\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.0\n\tgithub.com/go-chi/chi/v5 v5.0.0\n)\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := DetectFramework(dir); got != "" {
		t.Errorf("DetectFramework = %q, want \"\" (ambiguous — two frameworks present)", got)
	}
	frameworks := DetectFrameworks(dir)
	if !slicesEqualUnordered(frameworks, []string{"gin", "chi"}) {
		t.Errorf("DetectFrameworks = %v, want both gin and chi reported", frameworks)
	}
}

func TestDetectFrameworks_IgnoresIndirectDependencies(t *testing.T) {
	dir := t.TempDir()
	content := "module example.com/x\n\ngo 1.24\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.0\n\tgithub.com/go-chi/chi/v5 v5.0.0 // indirect\n)\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := DetectFramework(dir); got != "gin" {
		t.Errorf("DetectFramework = %q, want gin (chi is only an indirect dependency)", got)
	}
}

func TestAnalyze_AmbiguousFrameworkFallsBackToUnknown(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"go.mod": "module example.com/api\n\ngo 1.24\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.0\n\tgithub.com/go-chi/chi/v5 v5.0.0\n)\n",
		"main.go": `package main

import "net/http"

func Health(w http.ResponseWriter, r *http.Request) {}

func main() {
	http.HandleFunc("/health", Health)
}
`,
	})

	spec := analyze(t, dir, "")
	findEndpoint(t, spec, "GET", "/health")
}

func tagFilterFixture(t *testing.T) string {
	t.Helper()
	return writeProject(t, map[string]string{
		"go.mod": "module example.com/api\n\ngo 1.24\n",
		"main.go": `package main

import "github.com/gin-gonic/gin"

func main() {
	r := gin.Default()
	r.GET("/users", ListUsers)
	r.GET("/orders", ListOrders)
	r.Run()
}

func ListUsers(c *gin.Context)  { c.JSON(200, gin.H{}) }
func ListOrders(c *gin.Context) { c.JSON(200, gin.H{}) }
`,
	})
}

func TestAnalyze_TagsFilter_IncludeOnlyMatchingTag(t *testing.T) {
	dir := tagFilterFixture(t)
	cfg := &config.Config{
		ProjectPath: dir, Framework: "gin", DocType: "swagger",
		Title: "Test API", Version: "1.0.0", Tags: []string{"users"},
	}
	spec, err := NewAnalyzer(cfg).Analyze()
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(spec.Endpoints) != 1 || spec.Endpoints[0].Path != "/users" {
		t.Errorf("expected only /users, got %v", spec.Endpoints)
	}
}

func TestAnalyze_TagsFilter_ExcludeTag(t *testing.T) {
	dir := tagFilterFixture(t)
	cfg := &config.Config{
		ProjectPath: dir, Framework: "gin", DocType: "swagger",
		Title: "Test API", Version: "1.0.0", Tags: []string{"!orders"},
	}
	spec, err := NewAnalyzer(cfg).Analyze()
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(spec.Endpoints) != 1 || spec.Endpoints[0].Path != "/users" {
		t.Errorf("expected only /users (orders excluded), got %v", spec.Endpoints)
	}
}

func TestAnalyze_TagsFilter_Unset_KeepsEverything(t *testing.T) {
	dir := tagFilterFixture(t)
	spec := analyze(t, dir, "gin")
	if len(spec.Endpoints) != 2 {
		t.Errorf("expected both endpoints with no --tags filter, got %v", spec.Endpoints)
	}
}

func TestAnalyze_NetHTTP_MethodPatterns(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"go.mod": "module example.com/api\n\ngo 1.24\n",
		"main.go": `package main

import (
	"encoding/json"
	"net/http"
)

type Item struct {
	ID   string ` + "`json:\"id\"`" + `
	Name string ` + "`json:\"name\"`" + `
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /items", ListItems)
	mux.HandleFunc("POST /items", CreateItem)
	mux.HandleFunc("DELETE  api.example.com/items/{id}", DeleteItem)
	mux.HandleFunc("GET /files/{path...}", ServeFile)
	mux.HandleFunc("GET /{$}", Home)
	mux.HandleFunc("/legacy", Home)
	mux.HandleFunc("CONNECT /tunnel", Home)
	http.ListenAndServe(":8080", mux)
}

func ListItems(w http.ResponseWriter, r *http.Request) {}

// CreateItem creates an item.
func CreateItem(w http.ResponseWriter, r *http.Request) {
	var it Item
	json.NewDecoder(r.Body).Decode(&it)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(it)
}

func DeleteItem(w http.ResponseWriter, r *http.Request) {}
func ServeFile(w http.ResponseWriter, r *http.Request)  {}
func Home(w http.ResponseWriter, r *http.Request)       {}
`,
	})

	spec := analyze(t, dir, "")

	findEndpoint(t, spec, "GET", "/items")
	findEndpoint(t, spec, "GET", "/")
	findEndpoint(t, spec, "GET", "/legacy")

	create := findEndpoint(t, spec, "POST", "/items")
	if create.RequestTypeName != "Item" {
		t.Errorf("RequestTypeName = %q, want Item (from json.NewDecoder(r.Body).Decode(&it))", create.RequestTypeName)
	}
	if resp, ok := create.Responses[201]; !ok || resp.Content["application/json"].Schema.Properties["name"].Type != "string" {
		t.Errorf("Responses = %v, want 201 with the Item schema", create.Responses)
	}
	if !strings.Contains(create.Description, "creates an item") {
		t.Errorf("Description = %q, want it to include the doc comment", create.Description)
	}

	del := findEndpoint(t, spec, "DELETE", "/items/{id}")
	if len(del.Parameters) != 1 || del.Parameters[0].Name != "id" {
		t.Errorf("DeleteItem params = %+v, want a single path param \"id\"", del.Parameters)
	}

	file := findEndpoint(t, spec, "GET", "/files/{path}")
	if len(file.Parameters) != 1 || file.Parameters[0].Name != "path" {
		t.Errorf("ServeFile params = %+v, want a single path param \"path\"", file.Parameters)
	}

	for _, ep := range spec.Endpoints {
		if !strings.HasPrefix(ep.Path, "/") {
			t.Errorf("path %q does not start with /", ep.Path)
		}
		if ep.Method == "CONNECT" || ep.Path == "/tunnel" {
			t.Errorf("CONNECT can't be represented in OpenAPI 3.0, want it skipped, got %s %s", ep.Method, ep.Path)
		}
	}
}

func TestParseServeMuxPattern(t *testing.T) {
	tests := []struct {
		pattern, method, path string
		ok                    bool
	}{
		{"/items", "GET", "/items", true},
		{"POST /items", "POST", "/items", true},
		{"get /items", "GET", "/items", true},
		{"PUT\t/items/{id}", "PUT", "/items/{id}", true},
		{"example.com/items", "GET", "/items", true},
		{"PATCH example.com/items/{id}", "PATCH", "/items/{id}", true},
		{"GET /static/{rest...}", "GET", "/static/{rest}", true},
		{"GET /{$}", "GET", "/", true},
		{"GET /users/{$}", "GET", "/users/", true},
		{"CONNECT /tunnel", "", "", false},
		{"GET example.com", "", "", false},
	}
	for _, tt := range tests {
		method, path, ok := parseServeMuxPattern(tt.pattern)
		if method != tt.method || path != tt.path || ok != tt.ok {
			t.Errorf("parseServeMuxPattern(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tt.pattern, method, path, ok, tt.method, tt.path, tt.ok)
		}
	}
}

func TestAnalyze_IgnoresRoutesAndTypesInTestFiles(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"go.mod": "module example.com/api\n\ngo 1.24\n",
		"main.go": `package main

import "github.com/gin-gonic/gin"

type Payload struct {
	Name string ` + "`json:\"name\"`" + `
}

func main() {
	r := gin.Default()
	r.POST("/things", Create)
}

func Create(c *gin.Context) {
	var p Payload
	c.ShouldBindJSON(&p)
}
`,
		"main_test.go": `package main

import "github.com/gin-gonic/gin"

type Payload struct {
	TestOnly bool ` + "`json:\"test_only\"`" + `
}

func setupRouter() *gin.Engine {
	r := gin.New()
	r.GET("/only-in-tests", Create)
	return r
}
`,
	})

	spec := analyze(t, dir, "gin")

	for _, ep := range spec.Endpoints {
		if ep.Path == "/only-in-tests" {
			t.Errorf("route registered in a _test.go file leaked into the spec: %s %s", ep.Method, ep.Path)
		}
	}
	create := findEndpoint(t, spec, "POST", "/things")
	schema := spec.Models["Payload"]
	if _, ok := schema.Properties["name"]; !ok || create.RequestTypeName != "Payload" {
		t.Errorf("Payload schema = %+v, want the main.go definition (with \"name\"), not the _test.go one", schema)
	}
}

func TestAnalyze_EveryRefResolvesToAComponent(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"go.mod": "module example.com/api\n\ngo 1.24\n",
		"main.go": `package main

import "github.com/gin-gonic/gin"

type Address struct {
	City string ` + "`json:\"city\"`" + `
}

type Tag struct {
	Label string ` + "`json:\"label\"`" + `
}

type Category struct {
	Name     string     ` + "`json:\"name\"`" + `
	Children []Category ` + "`json:\"children\"`" + `
	Tags     [][]Tag    ` + "`json:\"tags\"`" + `
}

type Owner struct {
	Name string ` + "`json:\"name\"`" + `
}

type User struct {
	Addresses []Address ` + "`json:\"addresses\"`" + `
	Category  *Category ` + "`json:\"category\"`" + `
}

func main() {
	r := gin.Default()
	r.GET("/users", GetUser)
	r.GET("/local", GetLocal)
}

func GetUser(c *gin.Context) {
	c.JSON(200, User{})
}

func GetLocal(c *gin.Context) {
	type envelope struct {
		Owner Owner ` + "`json:\"owner\"`" + `
	}
	c.JSON(200, envelope{})
}
`,
	})

	spec := analyze(t, dir, "gin")

	check := func(where string, s models.Schema) {
		visitSchemaRefs(s, func(refName string) {
			if _, ok := spec.Models[refName]; !ok {
				t.Errorf("%s references #/components/schemas/%s, which is missing from Models", where, refName)
			}
		})
	}
	for _, ep := range spec.Endpoints {
		for status, resp := range ep.Responses {
			for _, c := range resp.Content {
				check(ep.Method+" "+ep.Path+" response "+strconv.Itoa(status), c.Schema)
			}
		}
	}
	for name, s := range spec.Models {
		check("model "+name, s)
	}
	for _, name := range []string{"User", "Address", "Category", "Tag", "Owner"} {
		if _, ok := spec.Models[name]; !ok {
			t.Errorf("Models is missing %s", name)
		}
	}
}
