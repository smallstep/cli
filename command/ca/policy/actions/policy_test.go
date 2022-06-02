package actions

import (
	"reflect"
	"testing"
)

func Test_remove(t *testing.T) {
	type args struct {
		item  string
		items []string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "empty-slice",
			args: args{
				item:  "test",
				items: []string{},
			},
			want: []string{},
		},
		{
			name: "empty-item",
			args: args{
				item:  "",
				items: []string{"item"},
			},
			want: []string{"item"},
		},
		{
			name: "ok",
			args: args{
				item:  "item1",
				items: []string{"item1", "item2"},
			},
			want: []string{"item2"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := remove(tt.args.item, tt.args.items); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("remove() = %v, want %v", got, tt.want)
			}
		})
	}
}
