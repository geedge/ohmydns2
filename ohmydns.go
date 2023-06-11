package main

//go:generate go run plugin_gen.go

import (
	_ "ohmydns2/core/plug"
	"ohmydns2/ohmain"
)

func main() {
	ohmain.Run()
}
