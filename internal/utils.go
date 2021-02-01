package internal

import (
	"os"
	"path/filepath"
	"strings"
)

// TildaToHome converts a path beginning with ~/ to the absolute path based in
// the current home directory. If that cannot be determined, path is returned
// unaltered.
func TildaToHome(path string) string {
	if path == "" {
		return ""
	}

	home, herr := os.UserHomeDir()
	if herr == nil && home != "" && strings.HasPrefix(path, "~/") {
		path = strings.TrimLeft(path, "~/")
		path = filepath.Join(home, path)
	}

	return path
}
