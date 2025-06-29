package jwt

import (
	"encoding/json"
	"testing"
)

func Test_GET_Datas(t *testing.T) {
	claims := MapClaims{
		"exp": float64(1751173980),
		"nbf": float64(1751173985),
		"iat": int64(1751173981),
		"aud": "aud test",
		"iss": "iss test",
		"sub": "sub test",

		"date": int64(1751173961),
		"string": "string test",
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

	res, err := claims.GetAudience()
	if err != nil {
		t.Fatal(err)
	}

	checkres := "aud test"
	if res != checkres {
		t.Errorf("GetAudience, got %v, want %v", res, checkres)
	}

	// =================

	res, err = claims.GetIssuer()
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
