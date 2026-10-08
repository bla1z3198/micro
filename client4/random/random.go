package random

import (
	"math/rand/v2" // Use v2 if on Go 1.22+, otherwise use standard math/rand
)

// No global variables!

// Return a simple struct to avoid heap allocations
type PartInfo struct {
	Parts uint16
	One   uint16
}

func Random(length int) PartInfo {
	val := rand.IntN(100) // Instantly gets a fast number 0-99
	var parts int

	// Check highest values FIRST
	switch {
	case val > 92:
		parts = 15 + rand.IntN(11)
	case val > 80:
		parts = 3 + rand.IntN(8)
	case val > 30:
		parts = 7 + rand.IntN(6)
	default:
		parts = 10 + rand.IntN(5)
	}

	return PartInfo{
		Parts: uint16(parts),
		One:   uint16(length / parts),
	}
}
