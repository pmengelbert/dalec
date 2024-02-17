package main

import (
	"fmt"
	"os"

	"github.com/Azure/dalec"
)

func main() {
	if len(os.Args) < 3 {
		panic("need args: filename, target")
	}
	filename := os.Args[1]
	tgt := os.Args[2]
	b, err := os.ReadFile(filename)
	if err != nil {
		panic(err)
	}

	allSpecs, err := dalec.LoadSpecs(b)
	if err != nil {
		panic(err)
	}

	if err := dalec.InitGraph(allSpecs, tgt); err != nil {
		panic(err)
	}

	o := dalec.BuildGraph.OrderedSlice(tgt)
	if err != nil {
		panic(err)
	}

	for _, spec := range o {
		fmt.Println(spec.Name)
	}
}
