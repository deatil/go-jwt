package jwt

import (
	"encoding/json"
	"testing"
	"time"
)

func Test_GET_Datas(t *testing.T) {
	claims := MapClaims{
		"exp": float64(1751173980),
		"nbf": float64(1751173985),
		"iat": int64(1751173981),
		"aud": "aud test",
		"iss": "iss test",
		"sub": "sub test",

		"date":   int64(1751173961),
		"string": "string test",
		"strings": []string{
			"string1 test",
			"string2 test",
		},
		"stringsany": []any{
			"string1 any test",
			"string2 any test",
		},
	}

	exp, err := claims.GetExpirationTime()
	if err != nil {
		t.Fatal(err)
	}

	expu := exp.Time.Unix()
	check := int64(1751173980)
	if expu != check {
		t.Errorf("GetExpirationTime, got %v, want %v", expu, check)
	}

	// =================

	nbf, err := claims.GetNotBefore()
	if err != nil {
		t.Fatal(err)
	}

	nbfu := nbf.Time.Unix()
	checknbf := int64(1751173985)
	if nbfu != checknbf {
		t.Errorf("GetNotBefore, got %v, want %v", nbfu, checknbf)
	}

	// =================

	iat, err := claims.GetIssuedAt()
	if err != nil {
		t.Fatal(err)
	}

	iatu := iat.Time.Unix()
	checkiat := int64(1751173981)
	if iatu != checkiat {
		t.Errorf("GetIssuedAt, got %v, want %v", iatu, checkiat)
	}

	// =================

	res1, err := claims.GetAudience()
	if err != nil {
		t.Fatal(err)
	}

	checkres := "aud test"
	if res1.Value[0] != checkres {
		t.Errorf("GetAudience, got %v, want %v", res1.Value[0], checkres)
	}

	// =================

	res1, err = claims.GetClaimsString("aud")
	if err != nil {
		t.Fatal(err)
	}

	checkres = "aud test"
	if res1.Value[0] != checkres {
		t.Errorf("GetClaimsString, got %v, want %v", res1.Value[0], checkres)
	}
	if !res1.AsString {
		t.Errorf("GetClaimsString AsString, got %v, want %v", res1.AsString, "true")
	}

	// =================

	res1, err = claims.GetClaimsString("strings")
	if err != nil {
		t.Fatal(err)
	}

	checkres = "string1 test"
	if res1.Value[0] != checkres {
		t.Errorf("GetClaimsString string, got %v, want %v", res1.Value[0], checkres)
	}

	// =================

	res1, err = claims.GetClaimsString("stringsany")
	if err != nil {
		t.Fatal(err)
	}

	checkres = "string2 any test"
	if res1.Value[1] != checkres {
		t.Errorf("GetClaimsString string, got %v, want %v", res1.Value[1], checkres)
	}
	if res1.AsString {
		t.Errorf("GetClaimsString AsString, got %v, want %v", res1.AsString, "false")
	}

	// =================

	res, err := claims.GetIssuer()
	if err != nil {
		t.Fatal(err)
	}

	checkres = "iss test"
	if res != checkres {
		t.Errorf("GetIssuer, got %v, want %v", res, checkres)
	}

	// =================

	res, err = claims.GetSubject()
	if err != nil {
		t.Fatal(err)
	}

	checkres = "sub test"
	if res != checkres {
		t.Errorf("GetSubject, got %v, want %v", res, checkres)
	}

	// =================

	nd, err := claims.GetNumericDate("date")
	if err != nil {
		t.Fatal(err)
	}

	ndu := nd.Time.Unix()
	checknd := int64(1751173961)
	if ndu != checknd {
		t.Errorf("GetNumericDate, got %v, want %v", ndu, checknd)
	}

	// =================

	res, err = claims.GetString("string")
	if err != nil {
		t.Fatal(err)
	}

	checkres = "string test"
	if res != checkres {
		t.Errorf("GetString, got %v, want %v", res, checkres)
	}

}

func Test_GET_Datas_error(t *testing.T) {
	claims := MapClaims{
		"exp": json.Number("1751173980"),
		"iat": int(1751173981),
		"nbf": "nbf string",
	}

	exp, err := claims.GetExpirationTime()
	if err != nil {
		t.Fatal(err)
	}

	expu := exp.Time.Unix()
	check := int64(1751173980)
	if expu != check {
		t.Errorf("GetExpirationTime, got %v, want %v", expu, check)
	}

	// =================

	_, err = claims.GetIssuedAt()
	if err == nil {
		t.Error("GetIssuedAt err")
	}
	checkerr := "invalid type for claim: iat is invalid"
	if err.Error() != checkerr {
		t.Errorf("GetIssuedAt err, got %s, want %s", err.Error(), checkerr)
	}

	// =================

	_, err = claims.GetNotBefore()
	if err == nil {
		t.Error("GetNotBefore err")
	}
	checkerr = "invalid type for claim: nbf is invalid"
	if err.Error() != checkerr {
		t.Errorf("GetNotBefore err, got %s, want %s", err.Error(), checkerr)
	}

	// =================

	_, err = claims.GetNumericDate("date2222")
	if err == nil {
		t.Error("GetNumericDate should return error")
	}

	checkerr = "invalid type for claim: date2222 is not exists"
	if err.Error() != checkerr {
		t.Errorf("GetNumericDate err, got %v, want %v", err.Error(), checkerr)
	}
}

func Test_MapClaims_parseString(t *testing.T) {
	type args struct {
		key string
	}
	tests := []struct {
		name    string
		m       MapClaims
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "missing key",
			m:    MapClaims{},
			args: args{
				key: "mykey",
			},
			want:    "",
			wantErr: false,
		},
		{
			name: "wrong key type",
			m:    MapClaims{"mykey": 4},
			args: args{
				key: "mykey",
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "correct key type",
			m:    MapClaims{"mykey": "mystring"},
			args: args{
				key: "mykey",
			},
			want:    "mystring",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.m.parseString(tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("MapClaims.parseString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("MapClaims.parseString() = %v, want %v", got, tt.want)
			}
		})
	}
}

type testRegisteredClaims struct {
	Issuer    ClaimStrings `json:"iss,omitempty"`
	Subject   ClaimStrings `json:"sub,omitempty"`
	Audience  ClaimStrings `json:"aud,omitempty"`
	ExpiresAt *NumericDate `json:"exp,omitempty"`
	IssuedAt  *NumericDate `json:"iat,omitempty"`
	String    string       `json:"string,omitempty"`
}

func Test_MarshalJSON(t *testing.T) {
	now := time.Now()
	exp := now.AddDate(0, 0, 5)

	claims := testRegisteredClaims{
		ExpiresAt: NewNumericDate(exp),
		IssuedAt:  NewNumericDate(now),
		Audience: ClaimStrings{
			Value: []string{
				"aud test",
			},
			// AsString: false,
		},
		Issuer: ClaimStrings{
			Value: []string{
				"iss test",
			},
			AsString: true,
		},
		Subject: ClaimStrings{
			Value: []string{
				"sub11 test",
				"sub22 test",
			},
			AsString: false,
		},
		String: "string test",
	}

	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}

	// =================

	var dst testRegisteredClaims
	err = json.Unmarshal(data, &dst)
	if err != nil {
		t.Fatal(err)
	}

	// =================

	getExp := dst.ExpiresAt

	expu := getExp.Time.Unix()
	checkexp := exp.Unix()
	if expu != checkexp {
		t.Errorf("GetNumericDate exp, got %v, want %v", expu, checkexp)
	}

	// =================

	getiat := dst.IssuedAt

	iatu := getiat.Time.Unix()
	checkiat := now.Unix()
	if iatu != checkiat {
		t.Errorf("GetNumericDate iat, got %v, want %v", iatu, checkiat)
	}

	// =================

	res1 := claims.String

	checkres := "string test"
	if res1 != checkres {
		t.Errorf("GetString, got %v, want %v", res1, checkres)
	}

	// =================

	res := claims.Audience

	checkres = "aud test"
	if res.Value[0] != checkres {
		t.Errorf("GetClaimsString aud, got %v, want %v", res.Value[1], checkres)
	}
	if res.AsString {
		t.Errorf("GetClaimsString aud AsString, got %v, want %v", res.AsString, "false")
	}

	// =================

	res = claims.Issuer

	checkres = "iss test"
	if res.Value[0] != checkres {
		t.Errorf("GetClaimsString iss, got %v, want %v", res.Value[0], checkres)
	}
	if !res.AsString {
		t.Errorf("GetClaimsString iss AsString, got %v, want %v", res.AsString, "true")
	}

	// =================

	res = claims.Subject

	checkres1 := "sub11 test"
	if res.Value[0] != checkres1 {
		t.Errorf("GetClaimsString sub, got %v, want %v", res.Value[0], checkres1)
	}
	checkres2 := "sub22 test"
	if res.Value[1] != checkres2 {
		t.Errorf("GetClaimsString sub, got %v, want %v", res.Value[1], checkres2)
	}
	if res.AsString {
		t.Errorf("GetClaimsString sub AsString, got %v, want %v", res.AsString, "false")
	}

}

func Test_RegisteredClaims_MarshalJSON(t *testing.T) {
	now := time.Now()
	exp := now.AddDate(0, 0, 5)
	nbf := now.AddDate(0, 0, 1)

	claims := RegisteredClaims{
		Issuer:  "iss test",
		Subject: "sub test",
		Audience: ClaimStrings{
			Value: []string{
				"aud test",
				"aud2 test",
			},
			AsString: false,
		},
		ExpiresAt: NewNumericDate(exp),
		NotBefore: NewNumericDate(nbf),
		IssuedAt:  NewNumericDate(now),
		ID:        "ID test",
	}

	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}

	// =================

	var dst RegisteredClaims
	err = json.Unmarshal(data, &dst)
	if err != nil {
		t.Fatal(err)
	}

	// =================

	getExp, _ := dst.GetExpirationTime()

	expu := getExp.Time.Unix()
	checkexp := exp.Unix()
	if expu != checkexp {
		t.Errorf("GetExpirationTime, got %v, want %v", expu, checkexp)
	}

	// =================

	getnbf, _ := dst.GetNotBefore()

	nbfu := getnbf.Time.Unix()
	checknbf := nbf.Unix()
	if nbfu != checknbf {
		t.Errorf("GetNotBefore, got %v, want %v", nbfu, checknbf)
	}

	// =================

	getiat, _ := dst.GetIssuedAt()

	iatu := getiat.Time.Unix()
	checkiat := now.Unix()
	if iatu != checkiat {
		t.Errorf("GetIssuedAt, got %v, want %v", iatu, checkiat)
	}

	// =================

	res1 := claims.ID

	checkres := "ID test"
	if res1 != checkres {
		t.Errorf("ID, got %v, want %v", res1, checkres)
	}

	// =================

	res1, _ = claims.GetIssuer()

	checkres = "iss test"
	if res1 != checkres {
		t.Errorf("GetIssuer, got %v, want %v", res1, checkres)
	}

	// =================

	res1, _ = claims.GetSubject()

	checkres = "sub test"
	if res1 != checkres {
		t.Errorf("GetSubject, got %v, want %v", res1, checkres)
	}

	// =================

	res2, _ := claims.GetAudience()

	checkres1 := "aud test"
	if res2.Value[0] != checkres1 {
		t.Errorf("GetAudience aud, got %v, want %v", res2.Value[0], checkres1)
	}
	checkres2 := "aud2 test"
	if res2.Value[1] != checkres2 {
		t.Errorf("GetAudience aud2, got %v, want %v", res2.Value[1], checkres2)
	}
	if res2.AsString {
		t.Errorf("GetAudience AsString, got %v, want %v", res2.AsString, "false")
	}

}

func Test_RegisteredClaims_MarshalJSON2(t *testing.T) {
	claims := MapClaims{
		"aud": []any{
			"aud test",
			"aud2 test",
		},
	}

	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}

	// =================

	var dst RegisteredClaims
	err = json.Unmarshal(data, &dst)
	if err != nil {
		t.Fatal(err)
	}

	// =================

	res2, _ := claims.GetAudience()

	checkres1 := "aud test"
	if res2.Value[0] != checkres1 {
		t.Errorf("GetAudience aud, got %v, want %v", res2.Value[0], checkres1)
	}
	checkres2 := "aud2 test"
	if res2.Value[1] != checkres2 {
		t.Errorf("GetAudience aud2, got %v, want %v", res2.Value[1], checkres2)
	}
	if res2.AsString {
		t.Errorf("GetAudience AsString, got %v, want %v", res2.AsString, "false")
	}

}

func Test_RegisteredClaims_MarshalJSON3(t *testing.T) {
	claims := MapClaims{
		"aud": nil,
	}

	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}

	// =================

	var dst RegisteredClaims
	err = json.Unmarshal(data, &dst)
	if err != nil {
		t.Fatal(err)
	}

	// =================

	res2, _ := claims.GetAudience()

	if len(res2.Value) > 0 {
		t.Errorf("GetAudience Value length, got %v, want %v", len(res2.Value), 0)
	}
	if res2.AsString {
		t.Errorf("GetAudience AsString, got %v, want %v", res2.AsString, "false")
	}

}
