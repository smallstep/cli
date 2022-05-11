package policycontext

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
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

func Test_hasPolicyLevelPanics(t *testing.T) {
	t.Parallel()
	//nolint:staticcheck // explicit test for a nil context
	assert.Panics(t, func() { isPolicyLevel(nil, authorityPolicyLevel) })
}
