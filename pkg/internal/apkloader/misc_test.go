package apkloader

import (
	"errors"
	"testing"
)

func TestLoaderError(t *testing.T) {
	origErr := errors.New("original error")

	le1 := &LoaderError{
		Op:   "open",
		Path: "test.apk",
		err:  origErr,
	}

	expected1 := "open test.apk: original error"
	if le1.Error() != expected1 {
		t.Errorf("le1.Error() = %q, want %q", le1.Error(), expected1)
	}

	le2 := &LoaderError{
		Op:  "parse",
		err: origErr,
	}

	expected2 := "parse: original error"
	if le2.Error() != expected2 {
		t.Errorf("le2.Error() = %q, want %q", le2.Error(), expected2)
	}

	if errors.Unwrap(le1) != origErr {
		t.Error("Unwrap returned wrong error")
	}
}

func TestMiscErrors(t *testing.T) {
	// Just touch some of the global error variables
	if errDexTooSmall.Error() != "dex: file too small" {
		t.Error("errDexTooSmall mismatch")
	}
	if errZipBomb.Error() != "zip: extraction limit exceeded (possible zip bomb)" {
		t.Error("errZipBomb mismatch")
	}
}
