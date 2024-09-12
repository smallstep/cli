//go:build integration
// +build integration

package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/smallstep/assert"
	"github.com/smallstep/cli-utils/usage"
)

func TestHelpQuality(t *testing.T) {
	cmd := NewCLICommand().setCommand("../bin/step help").setFlag("html", "./html").setFlag("report", "")
	cmd.run()

	raw, _ := os.ReadFile("./html/report.json")
	var report *usage.Report
	json.Unmarshal([]byte(raw), &report)

	expectations := make(map[string]usage.Section)
	expectations["COMMANDS"] = usage.Section{Name: "COMMANDS", Words: 0, Lines: 0}
	expectations["COPYRIGHT"] = usage.Section{Name: "COPYRIGHT", Words: 5, Lines: 1}
	expectations["DESCRIPTION"] = usage.Section{Name: "DESCRIPTION", Words: 8, Lines: 1}
	expectations["EXAMPLES"] = usage.Section{Name: "EXAMPLES", Words: 10, Lines: 1}
	expectations["EXIT CODES"] = usage.Section{Name: "EXIT CODES", Words: 12, Lines: 1}
	expectations["ONLINE"] = usage.Section{Name: "ONLINE", Words: 7, Lines: 1}
	expectations["OPTIONS"] = usage.Section{Name: "OPTIONS", Words: 6, Lines: 2}
	expectations["POSITIONAL ARGUMENTS"] = usage.Section{Name: "POSITIONAL ARGUMENTS", Words: 6, Lines: 2}
	expectations["PRINTING"] = usage.Section{Name: "PRINTING", Words: 23, Lines: 1}
	expectations["SECURITY CONSIDERATIONS"] = usage.Section{Name: "SECURITY CONSIDERATIONS", Words: 220, Lines: 25}
	expectations["STANDARDS"] = usage.Section{Name: "STANDARDS", Words: 45, Lines: 10}
	expectations["USAGE"] = usage.Section{Name: "USAGE", Words: 2, Lines: 1}
	expectations["VERSION"] = usage.Section{Name: "VERSION", Words: 3, Lines: 1}

	t.Run("Headlines consistency", func(t *testing.T) {
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
			fmt.Printf("%s: %d\n", item, count)

			// Let's say only upper case considered headlines
			if strings.ToUpper(item) == item {

				_, ok := expectations[item]
				msg := fmt.Sprintf("Unexpected headline %s might lead to inconsistent docs", item)
				assert.Equals(t, ok, true, msg)
			}
		}
	})

	t.Run("Thresholds", func(t *testing.T) {
		for _, expected := range expectations {
			entries := report.PerHeadline(expected.Name)

			for _, entry := range entries {
				msgw := fmt.Sprintf("Short on words (%d < %d) in %s (%s)", entry.Words, expected.Words, entry.Command, expected.Name)
				msgl := fmt.Sprintf("Short on lines (%d < %d) in %s (%s)", entry.Lines, expected.Lines, entry.Command, expected.Name)
				assert.True(t, entry.Words >= expected.Words, msgw)
				assert.True(t, entry.Lines >= expected.Lines, msgl)
			}
		}
	})

	t.Run("No TODOs", func(t *testing.T) {
		for _, top := range report.Report {
			for _, section := range top.Sections {
				msg := fmt.Sprintf("TODO found in %s (%s)", section.Command, section.Name)
				assert.False(t, strings.Contains(strings.ToUpper(section.Text), "TODO"), msg)
			}
		}
	})
}
