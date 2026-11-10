//go:build !linux

package server

import "fmt"

func readResourceUsage() (resourceReading, error) {
	return resourceReading{}, fmt.Errorf("resource collection requires Linux")
}
