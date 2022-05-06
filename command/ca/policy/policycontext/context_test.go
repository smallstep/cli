package policycontext

import (
	"context"
	"testing"
)

func Test_hasPolicyLevel(t *testing.T) {
	type args struct {
		ctx   context.Context
		level policyLevel
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "nil-context",
			args: args{
				ctx:   nil,
				level: authorityPolicyLevel,
			},
			want: false,
		},
		{
			name: "not-set",
			args: args{
				ctx:   context.Background(),
				level: authorityPolicyLevel,
			},
			want: false,
		},
		{
			name: "false",
			args: args{
				ctx:   WithAuthorityPolicyLevel(context.Background()),
				level: provisionerPolicyLevel,
			},
			want: false,
		},
		{
			name: "true",
			args: args{
				ctx:   WithAuthorityPolicyLevel(context.Background()),
				level: authorityPolicyLevel,
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPolicyLevel(tt.args.ctx, tt.args.level); got != tt.want {
				t.Errorf("hasPolicyLevel() = %v, want %v", got, tt.want)
			}
		})
	}
}
