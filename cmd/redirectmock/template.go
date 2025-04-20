package main

import (
	_ "embed"
	"html/template"
	"net/http"
)

//go:embed templates/login.html
var loginTemplate string

//go:embed static/login.css
var cssContent string

//go:embed static/login.js
var jsContent string

func RenderLogin(w http.ResponseWriter, r *http.Request) {
	// Create template data with the CSS and JavaScript content
	data := TemplateData{
		CSS: template.CSS(cssContent),
		JS:  template.JS(jsContent),
	}

	tmpl := template.New("login.html")
	tmpl, err := tmpl.Parse(loginTemplate)
	if err != nil {
		http.Error(w, "Failed to parse template: "+err.Error(), http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "Failed to execute template", http.StatusInternalServerError)
		return
	}
}
