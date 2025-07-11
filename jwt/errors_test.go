package jwt

import (
	"errors"
	"testing"
)

func Test_NewError(t *testing.T) {
	type args struct {
		message string
		err     error
		more    []error
	}
	tests := []struct {
		name        string
		args        args
		wantErrors  []error
		wantMessage string
	}{
		{
			name: "single error",
			args: args{
				message: "something is wrong",
				err:     ErrJWTInvalidType,
				more: []error{
					errors.New("test err"),
				},
			},
			wantMessage: "go-jwt: invalid type for claim: something is wrong: test err",
			wantErrors:  []error{ErrJWTInvalidType},
		},
		{
			name:        "single error",
			args:        args{message: "something is wrong", err: ErrJWTInvalidType},
			wantMessage: "go-jwt: invalid type for claim: something is wrong",
			wantErrors:  []error{ErrJWTInvalidType},
		},
		{
			name:        "single error",
			args:        args{err: ErrJWTInvalidType},
			wantMessage: "go-jwt: invalid type for claim",
			wantErrors:  []error{ErrJWTInvalidType},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewError(tt.args.message, tt.args.err, tt.args.more...)
			for _, wantErr := range tt.wantErrors {
				if !errors.Is(err, wantErr) {
					t.Errorf("NewError() error = %v, does not contain %v", err, wantErr)
				}
			}

			if err.Error() != tt.wantMessage {
				t.Errorf("NewError() error.Error() = %v, wantMessage %v", err, tt.wantMessage)
			}
		})
	}
}
