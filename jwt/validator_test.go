package jwt

import (
	"testing"
	"time"
)

func Test_Validator_isExpired(t *testing.T) {
	check1 := "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJleHAiOjE3Mzk4MTAzOTB9.dGVzdC1zaWduYXR1cmU"
	now := time.Now().Unix()

	var token = NewToken(JWTEncoder)
	token.Parse(check1)

	validator, err := NewValidator(token)
	if err != nil {
		t.Fatal(err)
	}

	isExpired := validator.IsExpired(now)
	if !isExpired {
		t.Errorf("IsExpired got %s, want %s", "false", "true")
	}

	if token.raw != check1 {
		t.Errorf("token raw got %s, want %s", token.raw, check1)
	}

	claims, err := token.GetClaims()
	if err != nil {
		t.Fatal(err)
	}
	if claims["exp"].(float64) < 0 {
		t.Errorf("GetClaims exp got %d", claims["exp"].(int))
	}
}

func Test_Validator(t *testing.T) {
	check1 := "eyJ0eXAiOiJKV0UiLCJhbGciOiJFUzI1NiIsImtpZCI6ImtpZHMifQ.eyJpc3MiOiJpc3MiLCJpYXQiOjE1Njc4NDIzODgsImV4cCI6MTc2Nzg0MjM4OCwiYXVkIjoiZXhhbXBsZS5jb20iLCJzdWIiOiJzdWIiLCJqdGkiOiJqdGkgcnJyIiwibmJmIjoxNTY3ODQyMzg4fQ.dGVzdC1zaWduYXR1cmU"
	now := time.Now().Unix()

	var token = NewToken(JWTEncoder)
	token.Parse(check1)

	validator, err := NewValidator(token)
	if err != nil {
		t.Fatal(err)
	}

	status := validator.HasBeenIssuedBy("iss")
	if !status {
		t.Errorf("HasBeenIssuedBy false")
	}
	status = validator.IsRelatedTo("sub")
	if !status {
		t.Errorf("IsRelatedTo false")
	}
	status = validator.IsIdentifiedBy("jti rrr")
	if !status {
		t.Errorf("IsIdentifiedBy false")
	}
	status = validator.IsPermittedFor("example.com")
	if !status {
		t.Errorf("IsPermittedFor false")
	}
	status = validator.HasBeenIssuedBefore(now)
	if !status {
		t.Errorf("HasBeenIssuedBefore false")
	}
	status = validator.IsExpired(now)
	if status {
		t.Errorf("IsExpired true")
	}

	claims, err := token.GetClaims()
	if err != nil {
		t.Fatal(err)
	}
	if claims["nbf"].(float64) <= 0 {
		t.Errorf("GetClaims nbf got %d", claims["nbf"].(int))
	}

	if claims["iat"].(float64) != 1567842388 {
		t.Errorf("GetClaims iat got %f, want %d", claims["iat"].(float64), 1567842388)
	}
	if claims["exp"].(float64) != 1767842388 {
		t.Errorf("GetClaims exp got %f, want %d", claims["exp"].(float64), 1767842388)
	}
	if claims["nbf"].(float64) != 1567842388 {
		t.Errorf("GetClaims nbf got %f, want %d", claims["nbf"].(float64), 1567842388)
	}

	status = validator.HasBeenIssuedBefore(1567842389)
	if !status {
		t.Errorf("HasBeenIssuedBefore false")
	}
	status = validator.IsMinimumTimeBefore(1567842389)
	if !status {
		t.Errorf("IsMinimumTimeBefore false")
	}
	status = validator.IsExpired(1767842389)
	if !status {
		t.Errorf("IsExpired false")
	}

	// ======

	var token2 = NewToken(JWTEncoder)
	token2.Parse(check1)

	validator2, err := NewValidator(token2)
	if err != nil {
		t.Fatal(err)
	}

	validator2.WithLeeway(3)

	status = validator2.HasBeenIssuedBefore(1567842391)
	if !status {
		t.Errorf("HasBeenIssuedBefore false")
	}
	status = validator2.HasBeenIssuedBefore(1567842384)
	if status {
		t.Errorf("HasBeenIssuedBefore true")
	}
	status = validator2.IsMinimumTimeBefore(1567842391)
	if !status {
		t.Errorf("IsMinimumTimeBefore false")
	}
	status = validator2.IsMinimumTimeBefore(1567842384)
	if status {
		t.Errorf("IsMinimumTimeBefore true")
	}
	status = validator2.IsExpired(1767842392)
	if !status {
		t.Errorf("IsExpired false")
	}
	status = validator2.IsExpired(1767842389)
	if status {
		t.Errorf("IsExpired true")
	}

}

func Test_Validator_Error(t *testing.T) {
	{
		check1 := "eyJ0eXAiOiJKV0UiLCJhbGciOiJFUzI1NiIsImtpZCI6ImtpZHMifQ.eyJpc3MiOiJpc3MiLCJpYXQiOjE1Njc4NDIzODgsImV4cCI6MTc2Nzg0MjM4OCwiYXVkIjoiZXhhbXBsZS5jb20iLCJzdWIiOiJzdWIiLCJqdGkiOiJqdGkgcnJyIiwibmJmIjoxNTY3O321Mzg4fQ.dGVzdC1zaWduYXR1cmU"

		var token = NewToken(JWTEncoder)
		token.Parse(check1)

		_, err := NewValidator(token)
		if err == nil {
			t.Error("NewValidator err")
		}

		checkerr := "invalid character ';' after object key:value pair"
		if err.Error() != checkerr {
			t.Errorf("NewValidator err, got %s, want %s", err.Error(), checkerr)
		}
	}

	{
		check1 := "eyJ0eXAiOiJKV0UiLCJhbGciOiJFUzI1NiIsImtpZCI6ImtpZHMifQ.eyJpc3MiOiJpc3MiLCJpYXQiOjE1Njc4NDIzODgsImV4cCI6MTc2Nzg0MjM4OCwiYXVkIjoiZXhhbXBsZS5jb20iLCJzdWIiOiJzdWIiLCJqdGkiOiJqdGkgcnJyIiwibmJmIjoxNTY3ODQyMzg4fQ.dGVzdC1zaWduYXR1cmU"

		var token = NewToken(JWTEncoder)
		token.Parse(check1)

		validator, err := NewValidator(token)
		if err != nil {
			t.Fatal(err)
		}

		status := validator.IsPermittedFor("example123.com")
		if status {
			t.Errorf("IsPermittedFor true")
		}
		status = validator.IsIdentifiedBy("jti rrr222")
		if status {
			t.Errorf("IsIdentifiedBy true")
		}
		status = validator.IsRelatedTo("sub22")
		if status {
			t.Errorf("IsRelatedTo true")
		}
		status = validator.HasBeenIssuedBy("iss22")
		if status {
			t.Errorf("HasBeenIssuedBy true")
		}
	}

	{
		check1 := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHBpcmVkIjoxNzExNTMxMTg4LCJ1c2VyX2lkIjoxMzM0fQ.CM4ZhL1vQ38p5hNo4Sody0ZYDo5_mSw16RsguC68664"

		var token = NewToken(JWTEncoder)
		token.Parse(check1)

		validator, err := NewValidator(token)
		if err != nil {
			t.Fatal(err)
		}

		status := validator.IsPermittedFor("example123.com")
		if status {
			t.Errorf("IsPermittedFor true")
		}
		status = validator.IsIdentifiedBy("jti rrr222")
		if status {
			t.Errorf("IsIdentifiedBy true")
		}
		status = validator.IsRelatedTo("sub22")
		if status {
			t.Errorf("IsRelatedTo true")
		}
		status = validator.HasBeenIssuedBy("iss22")
		if status {
			t.Errorf("HasBeenIssuedBy true")
		}
		status = validator.HasBeenIssuedBefore(1567842384)
		if !status {
			t.Errorf("HasBeenIssuedBefore false")
		}
		status = validator.IsMinimumTimeBefore(1567842391)
		if !status {
			t.Errorf("IsMinimumTimeBefore false")
		}
		status = validator.IsExpired(1767842392)
		if status {
			t.Errorf("IsExpired true")
		}
	}
}
