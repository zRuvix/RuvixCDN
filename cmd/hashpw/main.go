package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// hashpw prints a bcrypt hash for ADMIN_PASS_HASH. The password is read
// from argv[1] or, if absent, prompted on stdin (no echo handling —
// prefer the argv form only in throwaway shells, it leaks to history).
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "hashpw:", err)
		os.Exit(1)
	}
}

func run() error {
	pw := ""
	if len(os.Args) > 1 {
		pw = os.Args[1]
	} else {
		fmt.Fprint(os.Stderr, "password: ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			return err
		}
		pw = strings.TrimRight(line, "\r\n")
	}
	if pw == "" {
		return fmt.Errorf("empty password")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	fmt.Println(string(hash))
	return nil
}
