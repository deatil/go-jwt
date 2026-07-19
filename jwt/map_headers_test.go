package jwt

import (
	"testing"
)

func Test_MapHeaders_GET_Datas(t *testing.T) {
	headers := MapHeaders{
		"typ0": int64(1751173981),
		"typ":  "typ test",
		"alg":  "alg test",
		"kid":  "kid test",
		"cty":  "cty test",

		"inty":   int64(1751173981),
		"string": "string test",
		"strings": []string{
			"string1 test",
			"string2 test",
		},
	}

	_, err := headers.GetType()
	if err != nil {
		t.Fatal(err)
	}

	// =================

	res1, err := headers.GetType()
	if err != nil {
		t.Fatal(err)
	}

	checkres := "typ test"
	if res1 != checkres {
		t.Errorf("GetAlgorithm, got %v, want %v", res1, checkres)
	}

	// =================

	res, err := headers.GetAlgorithm()
	if err != nil {
		t.Fatal(err)
	}

	checkres = "alg test"
	if res != checkres {
		t.Errorf("GetAlgorithm, got %v, want %v", res, checkres)
	}

	// =================

	res, err = headers.GetKeyID()
	if err != nil {
		t.Fatal(err)
	}

	checkres = "kid test"
	if res != checkres {
		t.Errorf("GetKeyID, got %v, want %v", res, checkres)
	}

	// =================

	res, err = headers.GetContentType()
	if err != nil {
		t.Fatal(err)
	}

	checkres = "cty test"
	if res != checkres {
		t.Errorf("GetContentType, got %v, want %v", res, checkres)
	}

	// =================

	res, err = headers.GetString("string")
	if err != nil {
		t.Fatal(err)
	}

	checkres = "string test"
	if res != checkres {
		t.Errorf("GetString, got %v, want %v", res, checkres)
	}

	// =================

	_, err = headers.GetString("typ0")
	if err == nil {
		t.Fatal("GetString(typ0) should return error")
	}

	_, err = headers.GetString("strings")
	if err == nil {
		t.Fatal("GetString(strings) should return error")
	}

	_, err = headers.GetString("inty")
	checkerr := "go-jwt: invalid type for header: inty is invalid"
	if err.Error() != checkerr {
		t.Fatalf("GetString(inty) got %s, want %s", err, checkerr)
	}
}

func Test_MapHeaders_parseString(t *testing.T) {
	type args struct {
		key string
	}
	tests := []struct {
		name    string
		m       MapHeaders
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "missing key",
			m:    MapHeaders{},
			args: args{
				key: "mykey",
			},
			want:    "",
			wantErr: false,
		},
		{
			name: "wrong key type",
			m:    MapHeaders{"mykey": 4},
			args: args{
				key: "mykey",
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "correct key type",
			m:    MapHeaders{"mykey": "mystring"},
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
				t.Errorf("MapHeaders.parseString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("MapHeaders.parseString() = %v, want %v", got, tt.want)
			}
		})
	}
}
