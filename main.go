package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"slices"
	"strings"

	"github.com/tobischo/gokeepasslib/v3"
)

const (
	BUILD_VERSION = "1.2.0" // x-release-please-version

	INPUT_KEEPASS_FILE_PATH = "KEEPASS_FILE_PATH"
	INPUT_KEEPASS_PASSWORD  = "KEEPASS_PASSWORD"
)

var versionFlag bool

func init() {
	flag.BoolVar(&versionFlag, "V", false, "show version")
	flag.BoolVar(&versionFlag, "version", false, "show version")
}

func main() {
	// Parse input parameters
	flag.Parse()

	if versionFlag {
		fmt.Println(BUILD_VERSION)
		return
	}

	secretId := flag.Arg(0)
	if secretId == "" {
		log.Fatal("secret ID is empty")
	}

	// Find secret value
	secret, err := findSecret(secretId)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(secret)
}

func findSecret(secretId string) (secret string, err error) {
	// Client configuration
	dbPath := os.Getenv(INPUT_KEEPASS_FILE_PATH)
	if dbPath == "" {
		return secret, fmt.Errorf("environment variable %s is empty", INPUT_KEEPASS_FILE_PATH)
	}

	dbPass := os.Getenv(INPUT_KEEPASS_PASSWORD)
	if dbPass == "" {
		return secret, fmt.Errorf("environment variable %s is empty", INPUT_KEEPASS_PASSWORD)
	}

	// Open database file
	f, err := os.Open(dbPath)
	if err != nil {
		return
	}
	defer f.Close()

	// Decode and decrypt the database file
	kdb := gokeepasslib.NewDatabase()
	kdb.Credentials = gokeepasslib.NewPasswordCredentials(dbPass)
	err = gokeepasslib.NewDecoder(f).Decode(kdb)
	if err != nil {
		return
	}
	err = kdb.UnlockProtectedEntries()
	if err != nil {
		return
	}

	// Prepare for secret search
	uri := strings.Split(secretId, "/")
	path := &kdb.Content.Root.Groups[0]

	// Look through groups path, the last element is the secret entry
	for i := 0; i < len(uri)-1; i++ {
		path, err = findKeepassGroup(path.Groups, uri[i])
		if err != nil {
			return
		}
	}

	// Look for the secret
	secret, err = findKeepassEntry(path.Entries, uri[len(uri)-1])
	if err != nil {
		return
	}
	return
}

func findKeepassGroup(groups []gokeepasslib.Group, name string) (*gokeepasslib.Group, error) {
	idx := slices.IndexFunc(groups, func(grp gokeepasslib.Group) bool { return grp.Name == name })
	if idx == -1 {
		return &gokeepasslib.Group{}, fmt.Errorf("keepass group '%s' not found", name)
	}
	return &groups[idx], nil
}

func findKeepassEntry(entries []gokeepasslib.Entry, name string) (string, error) {
	// Split name into 'entry name' and 'key'
	nameSplit := strings.Split(name, ":")
	name = nameSplit[0]

	idx := slices.IndexFunc(entries, func(entry gokeepasslib.Entry) bool { return entry.GetTitle() == name })
	if idx == -1 {
		return "", fmt.Errorf("keepass entry '%s' not found", name)
	}

	// Content key exists
	if len(nameSplit) > 1 {
		return entries[idx].GetContent(nameSplit[1]), nil
	}
	return entries[idx].GetPassword(), nil
}
