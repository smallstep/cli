package sliceutil

// RemoveValues remove the given values from the given slice and returns the
// updated one. It retains the order of elements in the source slice.
func RemoveValues[T comparable](slice, values []T) []T {
	if len(slice) == 0 {
		return slice
	}
	keys := make(map[T]struct{}, len(slice))
	for _, v := range values {
		keys[v] = struct{}{}
	}

	var i int
	for _, v := range slice {
		if _, ok := keys[v]; !ok {
			slice[i] = v
			i++
		}
	}
	return slice[:i]
}

// RemoveDuplicates returns a new slice of T with duplicate values removed. It
// retains the order of elements in the source slice.
func RemoveDuplicates[T comparable](slice []T) []T {
	if len(slice) <= 1 {
		return slice
	}

	keys := make(map[T]struct{}, len(slice))
	ret := make([]T, 0, len(slice))
	for _, v := range slice {
		if _, ok := keys[v]; ok {
			continue
		}
		keys[v] = struct{}{}
		ret = append(ret, v)
	}
	return ret
}
