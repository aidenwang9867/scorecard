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
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/ossf/scorecard/v4/checker"

	sce "github.com/ossf/scorecard/v4/errors"
	sclog "github.com/ossf/scorecard/v4/log"
	"github.com/ossf/scorecard/v4/pkg"
)

// Depdiff is the exported name for dependency-diff.
const Depdiff = "Dependency-diff"

// A private context struct used for GetDependencyCheckResults.
type dependencydiffContext struct {
	logger                          *sclog.Logger
	ownerName, repoName, base, head string
	ctx                             context.Context
	changeTypesToCheck              []string
	checkNamesToRun                 []string
	dependencydiffs                 []dependency
	results                         []pkg.DependencyCheckResult
}

// GetDependencyDiffResults gets dependency changes between two given code commits BASE and HEAD
// along with the Scorecard check results of the dependencies, and returns a slice of DependencyCheckResult.
// TO use this API, an access token must be set. See https://github.com/ossf/scorecard#authentication.
func GetDependencyDiffResults(
	ctx context.Context,
	repoURI string, /* Use the format "ownerName/repoName" as the repo URI, such as "ossf/scorecard". */
	base, head string, /* Two code commits base and head, can use either SHAs or branch names. */
	checksToRun []string, /* A list of enabled check names to run. */
	changeTypes []string, /* A list of dependency change types for which we surface scorecard results. */
) ([]pkg.DependencyCheckResult, error) {
	logger := sclog.NewLogger(sclog.DefaultLevel)
	ownerAndRepo := strings.Split(repoURI, "/")
	if len(ownerAndRepo) != 2 {
		return nil, fmt.Errorf("%w: repo uri input", errInvalid)
	}
	owner, repo := ownerAndRepo[0], ownerAndRepo[1]
	dCtx := dependencydiffContext{
		logger:             logger,
		ownerName:          owner,
		repoName:           repo,
		base:               base,
		head:               head,
		ctx:                ctx,
		changeTypesToCheck: changeTypes,
		checkNamesToRun:    checksToRun,
	}
	// Fetch the raw dependency diffs. This API will also handle error cases such as invalid base or head.
	err := fetchRawDependencyDiffData(&dCtx)
	if err != nil {
		return nil, fmt.Errorf("error in fetchRawDependencyDiffData: %w", err)
	}
	// Map the ecosystem naming convention from GitHub to OSV.
	err = mapDependencyEcosystemNaming(dCtx.dependencydiffs)
	if err != nil {
		return nil, fmt.Errorf("error in mapDependencyEcosystemNaming: %w", err)
	}
	err = getScorecardCheckResults(&dCtx)
	if err != nil {
		return nil, fmt.Errorf("error getting scorecard check results: %w", err)
	}
	return dCtx.results, nil
}

func getScorecardCheckResults(dCtx *dependencydiffContext) error {
	for _, d := range dCtx.dependencydiffs {
		depCheckResult := pkg.DependencyCheckResult{
			PackageURL:       d.PackageURL,
			SourceRepository: d.SourceRepository,
			ChangeType:       d.ChangeType,
			ManifestPath:     d.ManifestPath,
			Ecosystem:        d.Ecosystem,
			Version:          d.Version,
			Name:             d.Name,
			/* The scorecard check result is nil for now. */
		}
		if d.ChangeType == nil {
			// Since we allow a dependency having a nil change type, so we also
			// give such a dependency a nil scorecard result.
			dCtx.results = append(dCtx.results, depCheckResult)
			continue
		}
		// (1) If no change types are specified, run the checks on all types of dependencies.
		// (2) If there are change types specified by the user, run the checks on the specified types.
		noneGivenOrIsSpecified := len(dCtx.changeTypesToCheck) == 0 || /* None specified.*/
			isSpecifiedByUser(*d.ChangeType, dCtx.changeTypesToCheck) /* Specified by the user.*/
		// For now we skip those without source repo urls.
		// TODO (#2063): use the BigQuery dataset to supplement null source repo URLs to fetch the Scorecard results for them.
		if d.SourceRepository != nil && noneGivenOrIsSpecified {
			parsedSrcRepo, err := url.Parse(*d.SourceRepository)
			if err != nil {
				return fmt.Errorf("error parsing source repo: %w", err)
			}
			// TODO (#2065): In future versions, ideally, we should use the commitSHA to query
			// the scorecard result for the specific commit of the repo.
			apiRequestURL := fmt.Sprintf(
				"https://api.securityscorecards.dev/projects/%s",
				// Remove the URL scheme ("http://", "https://")
				url.PathEscape(parsedSrcRepo.Host+parsedSrcRepo.Path),
			)
			resp, err := http.Get(apiRequestURL)
			if err != nil {
				return fmt.Errorf("error requesting the scorecard api: %w", err)
			}
			switch resp.StatusCode {
			case http.StatusOK:
				// Successfully fetched the repo scorecard result.
				err := json.NewDecoder(resp.Body).Decode(depCheckResult.ScorecardResultWithError.ScorecardResult)
				if err != nil {
					return fmt.Errorf("error parsing the returned scorecard result: %w", err)
				}
				// We only return those specified check results to the caller.
				// If none is specified, return all check results.
				if len(dCtx.checkNamesToRun) != 0 {
					var checksWanted []checker.CheckResult
					for _, c := range depCheckResult.ScorecardResultWithError.ScorecardResult.Checks {
						if checkIsSpecified(c.Name, dCtx.checkNamesToRun) {
							checksWanted = append(checksWanted, c)
						}
					}
					depCheckResult.ScorecardResultWithError.ScorecardResult.Checks = checksWanted
				}
				dCtx.results = append(dCtx.results, depCheckResult)
			default:
				// If the API query returns empty or fails, we leave the current scorecard result empty and record the error
				// rather than letting the entire API return nil since we still expect results for other dependencies.
				wrappedErr := sce.WithMessage(sce.ErrScorecardInternal,
					fmt.Sprintf("scorecard running failed for %s: %v", d.Name, err))
				dCtx.logger.Error(wrappedErr, "")
				depCheckResult.ScorecardResultWithError.Error = wrappedErr
			}
		}
		dCtx.results = append(dCtx.results, depCheckResult)
	}
	return nil
}

func isSpecifiedByUser(ct pkg.ChangeType, changeTypes []string) bool {
	if len(changeTypes) == 0 {
		return false
	}
	for _, ctByUser := range changeTypes {
		if string(ct) == ctByUser {
			return true
		}
	}
	return false
}

func checkIsSpecified(check string, checkNames []string) bool {
	for _, cn := range checkNames {
		if check == cn {
			return true
		}
	}
	return false
}
