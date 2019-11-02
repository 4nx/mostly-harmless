// Copyright 2019 Simon Krenz. All rights reserved.
// Use of this source code is governed by BSD license.

// Command file-copy is a simple zero-config tool to copy files.
// # go build file-copy.go
// # env GOOS=windows GOARCH=386/amd64 go build file-copy.go
package main

import (
	"fmt"
	"io"
	"os"
)

const usage = `Usage of file-copy:

	# file-copy <source> <destination>
	Copy the source file to destination
`

func main() {
	if len(os.Args) < 2 {
		fmt.Println(usage)
		os.Exit(1)
	}

	source := os.Args[1]
	destination := os.Args[2]

	src, err := os.Open(source)
	check(err)
	defer src.Close()

	dst, err := os.Create(destination)
	check(err)
	defer dst.Close()

	_, err = io.Copy(dst, src)
	check(err)
}

func check(err error) {
	if err != nil {
		fmt.Println("Error: %s", err.Error())
		os.Exit(1)
	}
}
