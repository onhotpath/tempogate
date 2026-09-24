package main

import (
	"go.uber.org/fx"

	"github.com/onhotpath/tempogate/app"
)

func main() {
	fx.New(app.New()).Run()
}
