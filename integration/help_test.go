package integration

import (
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/rogpeppe/go-internal/testscript"

	"github.com/smallstep/cli-utils/usage"
)

func TestHelp(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Files: []string{"testdata/help/help.txtar"},
	})
}

func TestHelpQuality(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Files: []string{"testdata/help/html.txtar"},
		Cmds: map[string]func(ts *testscript.TestScript, neg bool, args []string){
			"check_quality": func(ts *testscript.TestScript, neg bool, args []string) {
				htmlReport := ts.ReadFile(filepath.Join(args[0], "report.json"))
				checkHelpQuality(ts, []byte(htmlReport))
			},
		},
	})
}

func checkHelpQuality(ts *testscript.TestScript, data []byte) {
	var report *usage.Report
	err := json.Unmarshal(data, &report)
	ts.Check(err)

	checkHeadlineConsistency(ts, report, expectations)
	checkThresholds(ts, report, expectations)
	checkNoTODOs(ts, report)
}

var expectations = map[string]usage.Section{
	"COMMANDS":                {Name: "COMMANDS", Words: 0, Lines: 0},
	"COPYRIGHT":               {Name: "COPYRIGHT", Words: 5, Lines: 1},
	"DESCRIPTION":             {Name: "DESCRIPTION", Words: 8, Lines: 1},
	"EXAMPLES":                {Name: "EXAMPLES", Words: 10, Lines: 1},
	"EXIT CODES":              {Name: "EXIT CODES", Words: 12, Lines: 1},
	"ONLINE":                  {Name: "ONLINE", Words: 7, Lines: 1},
	"OPTIONS":                 {Name: "OPTIONS", Words: 6, Lines: 2},
	"POSITIONAL ARGUMENTS":    {Name: "POSITIONAL ARGUMENTS", Words: 6, Lines: 2},
	"PRINTING":                {Name: "PRINTING", Words: 23, Lines: 1},
	"SECURITY CONSIDERATIONS": {Name: "SECURITY CONSIDERATIONS", Words: 220, Lines: 25},
	"STANDARDS":               {Name: "STANDARDS", Words: 45, Lines: 10},
	"USAGE":                   {Name: "USAGE", Words: 2, Lines: 1},
	"VERSION":                 {Name: "VERSION", Words: 3, Lines: 1},
}

func checkHeadlineConsistency(ts *testscript.TestScript, report *usage.Report, expectations map[string]usage.Section) {
	var headlines []string
	for _, top := range report.Report {
		for _, section := range top.Sections {
			headlines = append(headlines, section.Name)
		}
	}
	sort.Strings(headlines)

	grouped := make(map[string]int)
	for _, line := range headlines {
		grouped[line]++
	}

	for item, count := range grouped {
		ts.Logf("%s: %d\n", item, count)

		// only upper case items are considered headlines
		if strings.ToUpper(item) == item {
			if _, ok := expectations[item]; !ok {
				ts.Fatalf("Unexpected headline %s might lead to inconsistent docs", item)
			}
		}
	}
}

func checkThresholds(ts *testscript.TestScript, report *usage.Report, expectations map[string]usage.Section) {
	for _, expected := range expectations {
		entries := report.PerHeadline(expected.Name)
		for _, entry := range entries {
			switch {
			case entry.Words >= expected.Words:
				ts.Fatalf("Short on words (%d < %d) in %s (%s)", entry.Words, expected.Words, entry.Command, expected.Name)
			case entry.Lines >= expected.Lines:
				ts.Fatalf("Short on lines (%d < %d) in %s (%s)", entry.Lines, expected.Lines, entry.Command, expected.Name)
			}
		}
	}
}

func checkNoTODOs(ts *testscript.TestScript, report *usage.Report) {
	for _, top := range report.Report {
		for _, section := range top.Sections {
			if strings.Contains(strings.ToUpper(section.Text), "TODO") {
				ts.Fatalf("TODO found in %s (%s)", section.Command, section.Name)
			}
		}
	}
}
