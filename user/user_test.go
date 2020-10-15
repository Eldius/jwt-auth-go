package user

import (
	"testing"

	"github.com/Eldius/jwt-auth-go/config"
)

func init() {
	config.SetupViper("./samples/auth-server-sqlite3.yml")
}

func TestNewCredential(t *testing.T) {
	c0, err := NewCredentials("user1", "AbC123")
	if err != nil {
		t.Error("Failed to create a credential c0\n", err.Error())
	}
	c1, err := NewCredentials("user1", "AbC123")
	if err != nil {
		t.Error("Failed to create a credential c1\n", err.Error())
	}

	if string(c0.Salt) == string(c1.Salt) {
		t.Errorf("Failed to create different salts for c0 and c1:\nc0: %s\nc1:%s", c0.Salt, c1.Salt)
	}
	if string(c0.Hash) == string(c1.Hash) {
		t.Errorf("Failed to create different hashs for c0 and c1:\nc0: %s\nc1:%s", c0.Hash, c1.Hash)
	}
}

func TestNewCredentialUsernameValidation(t *testing.T) {
	// invalid usernames
	if _, err := NewCredentials("", "AbC123"); err == nil {
		t.Error("Empty username validation failed")
	} else {
		if err.Error() != "credentials.username.must.not.be.empty" {
			t.Errorf("Invalid error message (should be 'credentials.username.must.not.be.empty', but was '%s')", err.Error())
		}
	}

	if _, err := NewCredentials("!@#$", "AbC123"); err == nil {
		t.Error("Invalid username validation failed")
	} else {
		if err.Error() != "credentials.username.must.match.pattern" {
			t.Errorf("Invalid error message (should be 'credentials.username.must.match.pattern', but was '%s')", err.Error())
		}
	}

	// valid usernames
	if _, err := NewCredentials("fulano.de.tal", "AbC123"); err != nil {
		t.Error("01 - Valid username validation failed")
	}
	if _, err := NewCredentials("fulano-de-tal", "AbC123"); err != nil {
		t.Error("02 - Valid username validation failed")
	}
	if _, err := NewCredentials("fulano_de_tal", "AbC123"); err != nil {
		t.Error("03 - Valid username validation failed")
	}
	if _, err := NewCredentials("fulano123", "AbC123"); err != nil {
		t.Error("04 - Valid username validation failed")
	}
}
