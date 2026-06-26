package collector

import (
	"errors"
	"strings"
	"testing"
)

func TestSanitizeError(t *testing.T) {
	t.Parallel()

	got := SanitizeError(errors.New("  first\nsecond\tthird  "))
	if got == nil || *got != "first second third" {
		t.Fatalf("SanitizeError() = %v", got)
	}
	long := SanitizeError(errors.New(strings.Repeat("x", 300)))
	if long == nil || len(*long) != 256 {
		t.Fatalf("expected 256-char sanitized error, got %v", long)
	}
	if SanitizeError(errors.New(" \n\t ")) != nil {
		t.Fatalf("empty sanitized error should be nil")
	}
}

func TestSanitizeDetails(t *testing.T) {
	t.Parallel()

	got := SanitizeDetails(map[string]string{
		" listener\nstate ": " ready\t now ",
		"empty":             " \n\t ",
	})
	if got["listener state"] != "ready now" {
		t.Fatalf("sanitized detail = %+v", got)
	}
	if _, exists := got["empty"]; exists {
		t.Fatalf("empty detail should be omitted: %+v", got)
	}
}
