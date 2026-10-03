package generator

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/devenock/specyl/pkg/analyzer"
	"github.com/devenock/specyl/pkg/config"
	"github.com/devenock/specyl/pkg/models"
)

func validateOpenAPI(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	doc, err := openapi3.NewLoader().LoadFromData(data)
	if err != nil {
		t.Fatalf("%s did not parse as OpenAPI: %v", path, err)
	}
	if err := doc.Validate(context.Background()); err != nil {
		t.Errorf("%s is not a valid OpenAPI 3.0 document: %v", path, err)
	}
}

func TestSwaggerGenerate_OutputIsValidOpenAPI(t *testing.T) {
	tests := []struct {
		name string
		spec *models.APISpec
	}{
		{"empty", &models.APISpec{Title: "Empty API", Version: "1.0.0"}},
		{
			"minimal",
			&models.APISpec{
				Title: "Minimal API", Version: "1.0.0",
				Endpoints: []models.Endpoint{
					{Method: "GET", Path: "/health", Responses: map[int]models.Response{200: {Description: "ok"}}},
				},
			},
		},
		{"kitchen sink", kitchenSinkSpec()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := &config.Config{Output: dir, Title: tt.spec.Title, Version: tt.spec.Version, Quiet: true}
			if err := NewSwaggerGenerator(cfg).Generate(tt.spec); err != nil {
				t.Fatalf("Generate: %v", err)
			}
			validateOpenAPI(t, filepath.Join(dir, "openapi.json"))
		})
	}
}

func TestSwaggerGenerate_RealProjectOutputIsValidOpenAPI(t *testing.T) {
	projectPath := filepath.Join("..", "..", "examples", "ecommerce-gin")
	if _, err := os.Stat(projectPath); err != nil {
		t.Skipf("example project not available: %v", err)
	}

	cfg := &config.Config{
		ProjectPath: projectPath,
		Framework:   "gin",
		DocType:     "swagger",
		Title:       "Ecommerce API",
		Version:     "1.0.0",
		Quiet:       true,
	}
	spec, err := analyzer.NewAnalyzer(cfg).Analyze()
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(spec.Endpoints) == 0 {
		t.Fatal("expected at least one endpoint from the example project")
	}

	dir := t.TempDir()
	cfg.Output = dir
	if err := NewSwaggerGenerator(cfg).Generate(spec); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	validateOpenAPI(t, filepath.Join(dir, "openapi.json"))
}

func TestSwaggerGenerate_AnalyzedProjectsAreValidOpenAPI(t *testing.T) {
	tests := []struct {
		name, framework, source string
	}{
		{
			// Go 1.22+ ServeMux patterns used to leak the method into the path ("GET /items").
			name: "net/http method patterns",
			source: `package main

import (
	"encoding/json"
	"net/http"
)

type Item struct {
	ID string ` + "`json:\"id\"`" + `
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /items/{id}", GetItem)
	mux.HandleFunc("POST /items", CreateItem)
}

func GetItem(w http.ResponseWriter, r *http.Request) {}

func CreateItem(w http.ResponseWriter, r *http.Request) {
	var it Item
	json.NewDecoder(r.Body).Decode(&it)
	json.NewEncoder(w).Encode(it)
}
`,
		},
		{
			// A struct referenced only through an array property used to be left out of components.
			name:      "refs nested in array properties",
			framework: "gin",
			source: `package main

import "github.com/gin-gonic/gin"

type Address struct {
	City string ` + "`json:\"city\"`" + `
}

type User struct {
	Addresses []Address ` + "`json:\"addresses\"`" + `
}

func main() {
	r := gin.Default()
	r.GET("/users", GetUser)
}

func GetUser(c *gin.Context) {
	c.JSON(200, User{})
}
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			projectPath := t.TempDir()
			files := map[string]string{
				"go.mod":  "module example.com/api\n\ngo 1.24\n",
				"main.go": tt.source,
			}
			for name, content := range files {
				if err := os.WriteFile(filepath.Join(projectPath, name), []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}

			cfg := &config.Config{
				ProjectPath: projectPath,
				Framework:   tt.framework,
				DocType:     "swagger",
				Title:       "Test API",
				Version:     "1.0.0",
				Quiet:       true,
			}
			spec, err := analyzer.NewAnalyzer(cfg).Analyze()
			if err != nil {
				t.Fatalf("Analyze: %v", err)
			}

			cfg.Output = t.TempDir()
			if err := NewSwaggerGenerator(cfg).Generate(spec); err != nil {
				t.Fatalf("Generate: %v", err)
			}
			validateOpenAPI(t, filepath.Join(cfg.Output, "openapi.json"))
		})
	}
}

func kitchenSinkSpec() *models.APISpec {
	return &models.APISpec{
		Title:       "Kitchen Sink API",
		Version:     "1.0.0",
		Description: "Exercises every schema shape at once.",
		BasePath:    "/api/v1",
		Servers:     []models.Server{{URL: "http://localhost:8080", Description: "dev"}},
		Endpoints: []models.Endpoint{
			{
				Method: "POST", Path: "/users", Tags: []string{"users"},
				Security: []map[string][]string{{"BearerAuth": {}}},
				RequestBody: &models.RequestBody{
					Required: true,
					Content: map[string]models.Content{"application/json": {
						Schema: models.Schema{Ref: "#/components/schemas/CreateUserRequest"},
					}},
				},
				Responses: map[int]models.Response{
					201: {Description: "Created", Content: map[string]models.Content{
						"application/json": {Schema: models.Schema{Ref: "#/components/schemas/User"}},
					}},
					400: {Description: "Bad Request", Content: map[string]models.Content{
						"application/json": {Schema: models.Schema{Type: "object"}},
					}},
				},
			},
			{
				Method: "DELETE", Path: "/users/{id}", Tags: []string{"users"},
				Parameters: []models.Parameter{{Name: "id", In: "path", Required: true, Schema: models.Schema{Type: "string"}}},
				Security:   []map[string][]string{{"BearerAuth": {}}},
				Responses:  map[int]models.Response{204: {Description: "No Content"}},
			},
		},
		Models: map[string]models.Schema{
			"CreateUserRequest": {
				Type:     "object",
				Required: []string{"email"},
				Properties: map[string]models.Schema{
					"email":   {Type: "string"},
					"balance": {Type: "number", Format: "double", Nullable: true},
				},
			},
			"User": {
				Type: "object",
				Properties: map[string]models.Schema{
					"id":    {Type: "string"},
					"email": {Type: "string"},
					"tags":  {Type: "array", Items: &models.Schema{Ref: "#/components/schemas/Tag"}},
					"meta":  {Type: "object"},
				},
			},
			"Tag": {
				Type:       "object",
				Properties: map[string]models.Schema{"name": {Type: "string"}},
			},
		},
	}
}
