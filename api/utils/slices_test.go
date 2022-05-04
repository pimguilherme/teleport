/*
Copyright 2022 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSliceContainsStr(t *testing.T) {
	tests := []struct {
		name         string
		slice        []string
		target       string
		wantContains bool
	}{
		{name: "does contain", slice: []string{"two", "one"}, target: "one", wantContains: true},
		{name: "does not contain", slice: []string{"two", "one"}, target: "five", wantContains: false},
		{name: "empty slice", slice: nil, target: "one", wantContains: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.wantContains, SliceContainsStr(tc.slice, tc.target))
		})
	}
}

func TestDeduplicate(t *testing.T) {
	tests := []struct {
		name         string
		in, expected []string
	}{
		{name: "empty slice", in: []string{}, expected: []string{}},
		{name: "slice with unique elements", in: []string{"a", "b"}, expected: []string{"a", "b"}},
		{name: "slice with duplicate elements", in: []string{"a", "b", "b", "a", "c"}, expected: []string{"a", "b", "c"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, Deduplicate(tc.in))
		})
	}
}
