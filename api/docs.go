package handler

import (
	"net/http"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>WhisperWire API Documentation</title>
  <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
  <style>
    body { margin: 0; padding: 0; }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-standalone-preset.js"></script>
  <script>
    window.onload = function() {
      const spec = ` + "`" + openAPISpec + "`" + `;
      window.ui = SwaggerUIBundle({
        spec: JSON.parse(spec),
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIStandalonePreset
        ],
        plugins: [
          SwaggerUIBundle.plugins.DownloadUrl
        ],
        layout: "StandaloneLayout"
      });
    };
  </script>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

const openAPISpec = `{
  "openapi": "3.0.3",
  "info": {
    "title": "WhisperWire API",
    "version": "1.0.0",
    "description": "Backend-only API for E2E secure messaging"
  },
  "servers": [
    {"url": "https://your-app.vercel.app", "description": "Production"},
    {"url": "http://localhost:8000", "description": "Local"}
  ],
  "paths": {
    "/api/health": {
      "get": {
        "tags": ["Health"],
        "summary": "Health check",
        "responses": {"200": {"description": "OK"}}
      }
    },
    "/api/auth/signup": {
      "post": {
        "tags": ["Auth"],
        "summary": "Register new user",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "email": {"type": "string"},
                  "password": {"type": "string"}
                },
                "required": ["email", "password"]
              }
            }
          }
        },
        "responses": {"200": {"description": "User created"}}
      }
    },
    "/api/auth/login": {
      "post": {
        "tags": ["Auth"],
        "summary": "Login user",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "email": {"type": "string"},
                  "password": {"type": "string"}
                },
                "required": ["email", "password"]
              }
            }
          }
        },
        "responses": {"200": {"description": "Login successful"}}
      }
    }
  }
}`
