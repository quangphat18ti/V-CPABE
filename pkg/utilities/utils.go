package utilities

import (
	"bytes"
	"github.com/cloudflare/bn256"
	"reflect"
)

// Equal compares two slices for equality (order matters)
// Uses generics with comparable constraint for type safety
func Equal[T comparable](a, b []T) bool {
	// Check if lengths are different
	if len(a) != len(b) {
		return false
	}

	// Compare each element at the same index
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}

// EqualAny compares two slices of any type using reflection
// Less type-safe but works with any type
func EqualAny(a, b interface{}) bool {
	va := reflect.ValueOf(a)
	vb := reflect.ValueOf(b)

	// Check if both are slices
	if va.Kind() != reflect.Slice || vb.Kind() != reflect.Slice {
		return false
	}

	// Check lengths
	if va.Len() != vb.Len() {
		return false
	}

	// Compare elements
	for i := 0; i < va.Len(); i++ {
		if !reflect.DeepEqual(va.Index(i).Interface(), vb.Index(i).Interface()) {
			return false
		}
	}

	return true
}

// EqualFunc compares two slices using a custom comparison function
// Useful for complex types or custom equality logic
func EqualFunc[T any](a, b []T, eq func(T, T) bool) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if !eq(a[i], b[i]) {
			return false
		}
	}

	return true
}

// DeepEqual is a wrapper around reflect.DeepEqual for slices
// Works with nested structures, maps, etc.
func DeepEqual[T any](a, b []T) bool {
	return reflect.DeepEqual(a, b)
}

func CompareGTByString(a, b *bn256.GT) bool {
	//return a.String() == b.String()
	return bytes.Equal(a.Marshal(), b.Marshal())
}

func CompareG2ByString(a, b *bn256.G2) bool {
	return bytes.Equal(a.Marshal(), b.Marshal())
}
