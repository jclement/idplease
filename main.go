package main

import (
	"embed"

	"github.com/jclement/idplease/cmd"
)

//go:embed templates
var templates embed.FS

func main() {
	cmd.SetTemplates(templates)
	cmd.Execute()
}
