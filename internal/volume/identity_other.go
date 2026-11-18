//go:build !windows

package volume

import "errors"

// Identify is only implemented on Windows so far.
func Identify(path string) (*Identity, error) {
	return nil, errors.New("identify is only supported on Windows")
}
