package jwt

import (
	"errors"
	"testing"
)

func Test_newError(t *testing.T) {
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
				err:     ErrInvalidType,
				more: []error{
					errors.New("test err"),
				},
			},
			wantMessage: "invalid type for claim: something is wrong: test err",
			wantErrors:  []error{ErrInvalidType},
		},
		{
			name:        "single error",
			args:        args{message: "something is wrong", err: ErrInvalidType},
			wantMessage: "invalid type for claim: something is wrong",
			wantErrors:  []error{ErrInvalidType},
		},
		{
			name:        "single error",
			args:        args{err: ErrInvalidType},
			wantMessage: "invalid type for claim",
			wantErrors:  []error{ErrInvalidType},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := newError(tt.args.message, tt.args.err, tt.args.more...)
			for _, wantErr := range tt.wantErrors {
				if !errors.Is(err, wantErr) {
					t.Errorf("newError() error = %v, does not contain %v", err, wantErr)
				}
			}

			if err.Error() != tt.wantMessage {
				t.Errorf("newError() error.Error() = %v, wantMessage %v", err, tt.wantMessage)
			}
		})
	}
}
