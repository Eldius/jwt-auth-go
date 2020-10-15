package hashtools

import (
	"testing"
)

func TestSalt(t *testing.T) {
	s0 := Salt()
	t.Log("s0:", s0)
	s1 := Salt()
	t.Log("s1:", s1)

	if string(s0) == string(s1) {
		t.Error("s0 equals s1")
	}
}

func TestHash(t *testing.T) {
	h0, err := Hash("ABC123", []byte("DEF456"))
	if err != nil {
		t.Error(err)
	}
	h1, err := Hash("ABC123", []byte("DEF456"))
	if err != nil {
		t.Error(err)
	}
	if string(h0) != string(h1) {
		t.Errorf("h0 must be equals h1")
	}
}

func TestHashKeyIsReproduceable(t *testing.T) {
	h0, err := HashKey("abc", []byte("123"))
	if err != nil {
		t.Errorf("Failed to hash the first key:\n%s\n---", err.Error())
	}
	h1, err := HashKey("abc", []byte("123"))
	if err != nil {
		t.Errorf("Failed to hash the second key:\n%s\n---", err.Error())
	}

	if string(h0) != string(h1) {
		t.Error("HAshed key 0 and key 1 must be equals, but are diffent")
	}
}

func TestHashKeyDiferentSaltsDiferentHashes(t *testing.T) {
	h0, err := HashKey("abc", []byte("123"))
	if err != nil {
		t.Errorf("Failed to hash the first key:\n%s\n---", err.Error())
	}
	h1, err := HashKey("abc", []byte("456"))
	if err != nil {
		t.Errorf("Failed to hash the second key:\n%s\n---", err.Error())
	}

	if string(h0) == string(h1) {
		t.Error("HAshed key 0 and key 1 must be different, but are diffent")
	}
}
