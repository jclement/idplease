package main

import (
	"embed"

	"github.com/jclement/idplease/cmd"
)

//go:embed templates templates/admin
var templates embed.FS

func main() {
	cmd.SetTemplates(templates)
	cmd.Execute()
}
