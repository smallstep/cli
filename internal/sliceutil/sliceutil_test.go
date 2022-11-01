package sliceutil

import (
	"reflect"
	"testing"
)

func TestRemoveValues(t *testing.T) {
	type args struct {
		slice  []int
		values []int
	}
	tests := []struct {
		name string
		args args
		want []int
	}{
		{"ok", args{[]int{1, 2, 3, 4, 5}, []int{1, 5, 2}}, []int{3, 4}},
		{"ok len(0)", args{[]int{}, []int{1, 5, 2}}, []int{}},
		{"ok not found", args{[]int{1, 2, 3, 4, 5}, []int{6, 7, 8}}, []int{1, 2, 3, 4, 5}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RemoveValues(tt.args.slice, tt.args.values); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RemoveValues() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRemoveDuplicates(t *testing.T) {
	type args struct {
		slice []int
	}
	tests := []struct {
		name string
		args args
		want []int
	}{
		{"ok", args{[]int{1, 1, 2, 3, 4, 2, 5, 5, 1}}, []int{1, 2, 3, 4, 5}},
		{"ok len(0)", args{[]int{}}, []int{}},
		{"ok len(1)", args{[]int{1}}, []int{1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RemoveDuplicates(tt.args.slice); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RemoveDuplicates() = %v, want %v", got, tt.want)
			}
		})
	}
}
