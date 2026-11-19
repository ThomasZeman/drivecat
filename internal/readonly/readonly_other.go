//go:build !windows

package readonly

import (
	"errors"
	"os"
)

// Open is only implemented on Windows so far.
func Open(path string) (*os.File, error) {
	return nil, errors.New("readonly.Open is only supported on Windows")
}

// ReadDir is only implemented on Windows so far.
func ReadDir(path string) ([]Entry, error) {
	return nil, errors.New("readonly.ReadDir is only supported on Windows")
}
