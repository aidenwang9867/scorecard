// Copyright 2022 Security Scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dependencydiff

import (
	"context"
	"errors"
	"strings"
	"testing"

	sclog "github.com/ossf/scorecard/v4/log"
	"github.com/ossf/scorecard/v4/pkg"
)

func Test_getScorecardCheckResults(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		dCtx    dependencydiffContext
		wantErr bool
	}{
		{
			name: "empty response",
			dCtx: dependencydiffContext{
				ctx:       context.Background(),
				logger:    sclog.NewLogger(sclog.InfoLevel),
				ownerName: "owner_not_exist",
				repoName:  "repo_not_exist",
			},
			wantErr: false,
		},
		{
			name: "empty response",
			dCtx: dependencydiffContext{
				ctx:       context.Background(),
				logger:    sclog.NewLogger(sclog.InfoLevel),
				ownerName: "owner",
				repoName:  "repo",
				dependencydiffs: []dependency{
					{
						Name:       "dep_a",
						Ecosystem:  asPointer("gomod"),
						ChangeType: (*pkg.ChangeType)(asPointer("added")),
					},
					{
						Name:             "dep_b",
						Ecosystem:        asPointer("pip"),
						ChangeType:       (*pkg.ChangeType)(asPointer("removed")),
						SourceRepository: asPointer("https://dep_b_host/dep_b/v5"),
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := getScorecardCheckResults(&tt.dCtx)
			if (err != nil) != tt.wantErr {
				t.Errorf("getScorecardCheckResults() error = {%v}, want error: %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_mapDependencyEcosystemNaming(t *testing.T) {
	t.Parallel()
	//nolint
	tests := []struct {
		name      string
		deps      []dependency
		errWanted error
	}{
		{
			name: "error invalid github ecosystem",
			deps: []dependency{
				{
					Name:      "dependency_1",
					Ecosystem: asPointer("not_supported"),
				},
				{
					Name:      "dependency_2",
					Ecosystem: asPointer("gomod"),
				},
			},
			errWanted: errInvalid,
		},
		{
			name: "error cannot find mapping",
			deps: []dependency{
				{
					Name:      "dependency_3",
					Ecosystem: asPointer("foobar"),
				},
			},
			errWanted: errMappingNotFound,
		},
		{
			name: "correct mapping",
			deps: []dependency{
				{
					Name:      "dependency_4",
					Ecosystem: asPointer("gomod"),
				},
				{
					Name:      "dependency_5",
					Ecosystem: asPointer("pip"),
				},
				{
					Name:      "dependency_6",
					Ecosystem: asPointer("cargo"),
				},
				{
					Name:      "dependency_7",
					Ecosystem: asPointer("actions"),
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := mapDependencyEcosystemNaming(tt.deps)
			if tt.errWanted != nil && errors.Is(tt.errWanted, err) {
				t.Errorf("not a wanted error, want:%v, got:%v", tt.errWanted, err)
				return
			}
		})
	}
}

func Test_isSpecifiedByUser(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		ct                 pkg.ChangeType
		changeTypesToCheck []string
		resultWanted       bool
	}{
		{
			name: "error invalid github ecosystem",
		},
		{
			name:               "added",
			ct:                 pkg.ChangeType("added"),
			changeTypesToCheck: nil,
			resultWanted:       false,
		},
		{
			name:               "ct is added but not specified",
			ct:                 pkg.ChangeType("added"),
			changeTypesToCheck: []string{"removed"},
			resultWanted:       false,
		},
		{
			name:               "removed",
			ct:                 pkg.ChangeType("added"),
			changeTypesToCheck: []string{"added", "removed"},
			resultWanted:       true,
		},
		{
			name:               "not_supported",
			ct:                 pkg.ChangeType("not_supported"),
			changeTypesToCheck: []string{"added", "removed"},
			resultWanted:       false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := isSpecifiedByUser(tt.ct, tt.changeTypesToCheck)
			if result != tt.resultWanted {
				t.Errorf("result (%v) != result wanted (%v)", result, tt.resultWanted)
				return
			}
		})
	}
}

func Test_GetDependencyDiffResults(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		repoURI     string
		errContains string
	}{
		{
			name:        "invalid repo uri 1",
			repoURI:     "a invalid repo uri",
			errContains: "repo uri input",
		},
		{
			name:        "invalid repo uri 2",
			repoURI:     "another/invalid.repo//uri",
			errContains: "repo uri input",
		},
		{
			name:        "error fetching data",
			repoURI:     "valid/repouri",
			errContains: "fetchRawDependencyDiffData",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := GetDependencyDiffResults(context.Background(), tt.repoURI, "base", "head", nil, nil)
			if err != nil && !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("want err contains: %v, got %v", tt.errContains, err)
				return
			}
		})
	}
}
