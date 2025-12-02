package main

import (
	"flag"
	"os"
	"testing"

	"github.com/tobischo/gokeepasslib/v3"
	"github.com/tobischo/gokeepasslib/v3/wrappers"
)

const (
	KEEPASS_FILE_PATH = "Database.kdbx"
	KEEPASS_PASSWORD  = "default123"
)

func mkValue(key string, value string) gokeepasslib.ValueData {
	return gokeepasslib.ValueData{Key: key, Value: gokeepasslib.V{Content: value}}
}

func mkProtectedValue(key string, value string) gokeepasslib.ValueData {
	return gokeepasslib.ValueData{
		Key:   key,
		Value: gokeepasslib.V{Content: value, Protected: wrappers.NewBoolWrapper(true)},
	}
}

func setupDb() *gokeepasslib.Database {
	// create root group
	rootGroup := gokeepasslib.NewGroup()
	rootGroup.Name = "root group"

	entry := gokeepasslib.NewEntry()
	entry.Values = append(entry.Values, mkValue("Title", "My GMail password"))
	entry.Values = append(entry.Values, mkValue("UserName", "example@gmail.com"))
	entry.Values = append(entry.Values, mkProtectedValue("Password", "hunter2"))

	rootGroup.Entries = append(rootGroup.Entries, entry)

	// demonstrate creating sub group (we'll leave it empty because we're lazy)
	subGroup := gokeepasslib.NewGroup()
	subGroup.Name = "sub group"

	subEntry := gokeepasslib.NewEntry()
	subEntry.Values = append(subEntry.Values, mkValue("Title", "Another password"))
	subEntry.Values = append(subEntry.Values, mkValue("UserName", "johndough"))
	subEntry.Values = append(subEntry.Values, mkProtectedValue("Password", "123456"))

	subGroup.Entries = append(subGroup.Entries, subEntry)

	rootGroup.Groups = append(rootGroup.Groups, subGroup)

	// now create the database containing the root group
	return &gokeepasslib.Database{
		Header:      gokeepasslib.NewHeader(),
		Credentials: gokeepasslib.NewPasswordCredentials(KEEPASS_PASSWORD),
		Content: &gokeepasslib.DBContent{
			Meta: gokeepasslib.NewMetaData(),
			Root: &gokeepasslib.RootData{
				Groups: []gokeepasslib.Group{rootGroup},
			},
		},
	}
}

func TestMain(m *testing.M) {
	flag.Parse()

	os.Setenv(INPUT_KEEPASS_FILE_PATH, KEEPASS_FILE_PATH)
	os.Setenv(INPUT_KEEPASS_PASSWORD, KEEPASS_PASSWORD)

	f, err := os.Create(KEEPASS_FILE_PATH)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	// Create KeePass file
	kdb := setupDb()
	kdb.LockProtectedEntries()
	keepassEncoder := gokeepasslib.NewEncoder(f)
	if err := keepassEncoder.Encode(kdb); err != nil {
		panic(err)
	}

	os.Exit(m.Run())
}

func TestMainFunc(t *testing.T) {
	// Redirect standard out to null
	stdout := os.Stdout
	defer func() {
		os.Stdout = stdout
		os.Args = os.Args[:len(os.Args)-1]
	}()
	os.Stdout = os.NewFile(0, os.DevNull)

	os.Args = append(os.Args, "My GMail password")
	main()
}

func TestVersionFlag(t *testing.T) {
	// Redirect standard out to null
	stdout := os.Stdout
	defer func() {
		os.Stdout = stdout
		os.Args = os.Args[:len(os.Args)-1]
	}()
	os.Stdout = os.NewFile(0, os.DevNull)

	os.Args = append(os.Args, "-V")
	main()
}

func TestFindSecret(t *testing.T) {
	var tests = []struct {
		input              string
		want               string
		envKeepassFilePath string
		envKeepassPassword string
	}{
		{"sub group/Another password", "", KEEPASS_FILE_PATH, KEEPASS_PASSWORD},
		{"sub group/Another password", "environment variable KEEPASS_FILE_PATH is empty", "", ""},
		{"sub group/Another password", "environment variable KEEPASS_PASSWORD is empty", KEEPASS_FILE_PATH, ""},
		{"sub group/Another password", "open undefined: no such file or directory", "undefined", KEEPASS_PASSWORD},
		{"sub group/Another password", "Wrong password? Database integrity check failed", KEEPASS_FILE_PATH, "undefined"},
		{"sub group/Yet another password", "keepass entry 'Yet another password' not found", KEEPASS_FILE_PATH, KEEPASS_PASSWORD},
		{"undefined group/Another password", "keepass group 'undefined group' not found", KEEPASS_FILE_PATH, KEEPASS_PASSWORD},
	}

	for _, test := range tests {
		os.Setenv(INPUT_KEEPASS_FILE_PATH, test.envKeepassFilePath)
		os.Setenv(INPUT_KEEPASS_PASSWORD, test.envKeepassPassword)

		_, got := findSecret(test.input)
		if got != nil && got.Error() != test.want {
			t.Errorf("findSecret(%q) = %q, wanted %q", test.input, got, test.want)
		}
	}
}

func TestFindKeepassGroup(t *testing.T) {
	var tests = []struct {
		input string
		want  string
	}{
		{"nonexistent", "keepass group 'nonexistent' not found"},
		{"sub group", ""},
	}

	kdb := setupDb()
	path := &kdb.Content.Root.Groups[0].Groups

	for _, test := range tests {
		_, got := findKeepassGroup(*path, test.input)
		if got != nil && got.Error() != test.want {
			t.Errorf("findKeepassGroup(_, %q) = %q, wanted %q", test.input, got, test.want)
		}
	}
}

func TestFindKeepassEntry(t *testing.T) {
	kdb := setupDb()

	rootPath := &kdb.Content.Root.Groups[0].Entries
	subPath := &kdb.Content.Root.Groups[0].Groups[0].Entries

	var tests = []struct {
		db    *[]gokeepasslib.Entry
		input string
		want  string
	}{
		{rootPath, "Another password", ""},
		{rootPath, "My GMail password:Password", "hunter2"},
		{rootPath, "My GMail password:Title", "My GMail password"},
		{rootPath, "My GMail password:UserName", "example@gmail.com"},
		{rootPath, "My GMail password", "hunter2"},
		{subPath, "Another password:Password", "123456"},
		{subPath, "Another password:Title", "Another password"},
		{subPath, "Another password:UserName", "johndough"},
		{subPath, "Another password", "123456"},
		{subPath, "My GMail password", ""},
	}

	for _, test := range tests {
		got, _ := findKeepassEntry(*test.db, test.input)
		if got != test.want {
			t.Errorf("findKeepassEntry(%v, %q) = %q, wanted %q", test.db, test.input, got, test.want)
		}
	}
}
