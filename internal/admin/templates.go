package admin

import (
	"embed"
	"html/template"
)

// ParseTemplates parses all admin templates with the required FuncMap
func ParseTemplates(templates embed.FS) (*template.Template, error) {
	funcMap := template.FuncMap{
		"map": func(pairs ...interface{}) map[string]interface{} {
			m := make(map[string]interface{})
			for i := 0; i+1 < len(pairs); i += 2 {
				key, ok := pairs[i].(string)
				if ok {
					m[key] = pairs[i+1]
				}
			}
			return m
		},
	}

	tmpl := template.New("").Funcs(funcMap)

	// Parse login and error templates
	tmpl, err := tmpl.ParseFS(templates, "templates/login.html")
	if err != nil {
		return nil, err
	}
	tmpl, err = tmpl.ParseFS(templates, "templates/error.html")
	if err != nil {
		return nil, err
	}

	// Parse admin templates
	tmpl, err = tmpl.ParseFS(templates, "templates/admin/*.html")
	if err != nil {
		return nil, err
	}

	return tmpl, nil
}

// ParseTestTemplates parses templates from the testdata directory
func ParseTestTemplates(templates embed.FS) (*template.Template, error) {
	funcMap := template.FuncMap{
		"map": func(pairs ...interface{}) map[string]interface{} {
			m := make(map[string]interface{})
			for i := 0; i+1 < len(pairs); i += 2 {
				key, ok := pairs[i].(string)
				if ok {
					m[key] = pairs[i+1]
				}
			}
			return m
		},
	}

	tmpl := template.New("").Funcs(funcMap)
	// Try testdata/*.html first (may contain login.html, error.html, etc.)
	tmpl, err := tmpl.ParseFS(templates, "testdata/*.html")
	if err != nil {
		// Try testdata/templates/admin/*.html (server tests)
		tmpl2 := template.New("").Funcs(funcMap)
		tmpl2, err2 := tmpl2.ParseFS(templates, "testdata/templates/admin/*.html")
		if err2 != nil {
			return nil, err // return original error
		}
		return tmpl2, nil
	}
	return tmpl, nil
}
