// +build integration

package integration

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"sort"
	"strings"
	"testing"

	"github.com/smallstep/assert"
	"github.com/smallstep/cli/usage"
)

func TestHelpQuality(t *testing.T) {
	cmd := NewCLICommand().setCommand("../bin/step help").setFlag("html", "./html").setFlag("report", "")
	cmd.run()

	t.Run("Headlines consistency", func(t *testing.T) {
		raw, _ := ioutil.ReadFile("./html/report.json")
		var report *usage.Report
		json.Unmarshal([]byte(raw), &report)

		expected := map[string]bool{"COMMANDS": true, "COPYRIGHT": true, "DESCRIPTION": true,
			"EXAMPLES": true, "EXIT CODES": true, "ONLINE": true, "OPTIONS": true, "POSITIONAL ARGUMENTS": true,
			"PRINTING": true, "SECURITY CONSIDERATIONS": true, "STANDARDS": true, "USAGE": true, "VERSION": true}

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

			// Let's say only upper case is a headline
			if strings.ToUpper(item) == item {
				_, ok := expected[item]
				msg := fmt.Sprintf("Unexpected headline %s might lead to inconsistent docs", item)
				assert.Equals(t, ok, true, msg)
			}
		}
	})
}
