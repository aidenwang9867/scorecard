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

package depdiff

import (
	"errors"
)

var (
	// ErrInvalidDepDiffFormat indicates the specified dependency diff output format is not valid.
	ErrInvalidDepDiffFormat = errors.New("invalid depdiff format")

	// ErrDepDiffFormatNotSupported indicates the specified dependency diff output format is not supported.
	ErrDepDiffFormatNotSupported = errors.New("depdiff format not supported")

	// ErrInvalidDepDiffFormat indicates the specified dependency diff output format is not valid.
	ErrMarshalDepDiffToJSON = errors.New("error marshal results to JSON")
)
