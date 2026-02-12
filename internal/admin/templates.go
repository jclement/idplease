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

	// Parse login template
	tmpl, err := tmpl.ParseFS(templates, "templates/login.html")
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
	tmpl, err := tmpl.ParseFS(templates, "testdata/*.html")
	if err != nil {
		return nil, err
	}
	return tmpl, nil
}
