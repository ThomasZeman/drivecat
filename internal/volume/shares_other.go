//go:build !windows

package volume

import "errors"

// ListShares is only implemented on Windows so far.
func ListShares(server string) ([]Share, error) {
	return nil, errors.New("listing shares is only supported on Windows")
}
