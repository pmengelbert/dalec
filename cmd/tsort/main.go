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

	graph, err := dalec.BuildGraph(allSpecs)
	if err != nil {
		panic(err)
	}

	o := graph.Ordered()
	if err != nil {
		panic(err)
	}

	t, err := o.TargetSlice(tgt)
	if err != nil {
		panic(err)
	}

	for _, spec := range t {
		fmt.Println(spec.Name)
	}
}