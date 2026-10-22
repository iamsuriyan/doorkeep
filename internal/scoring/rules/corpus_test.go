package rules

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/iamsuriyan/doorkeep/internal/scoring"
)

// corpusCase is one file in testing/corpus (see its README).
type corpusCase struct {
	Name     string `json:"name"`
	Source   string `json:"source"`
	Action   string `json:"action"`
	Features struct {
		Num map[string]float64 `json:"num"`
		Cat map[string]string  `json:"cat"`
	} `json:"features"`
	Expect struct {
		Outcome  scoring.Outcome `json:"outcome"`
		MinRisk  *int            `json:"min_risk"`
		MaxRisk  *int            `json:"max_risk"`
		Fires    []string        `json:"fires"`
		NotFires []string        `json:"not_fires"`
		Note     string          `json:"note"`
	} `json:"expect"`
}

func (c *corpusCase) vector() (f scoring.Features, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r) // unknown feature key or category
		}
	}()
	f = scoring.NewFeatures()
	for k, v := range c.Features.Num {
		f.Set(k, v)
	}
	for k, v := range c.Features.Cat {
		f.SetCat(k, v)
		if f.Cat[k] != v {
			return f, fmt.Errorf("%s: %q is not a registered value", k, v)
		}
	}
	return f, nil
}

// TestGoldenCorpus runs every labelled vector in testing/corpus through the
// built-in rules and the decision engine (default thresholds, enforce).
func TestGoldenCorpus(t *testing.T) {
	files, _ := filepath.Glob("../../../testing/corpus/*.json")
	if len(files) == 0 {
		t.Fatal("testing/corpus is empty")
	}
	set := builtin(t)
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			b, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var c corpusCase
			if err := json.Unmarshal(b, &c); err != nil {
				t.Fatal(err)
			}
			if c.Name == "" || c.Source == "" || c.Expect.Outcome == "" {
				t.Fatal("name, source and expect.outcome are required")
			}
			f, err := c.vector()
			if err != nil {
				t.Fatal(err)
			}
			action := c.Action
			if action == "" {
				action = "default"
			}
			res := set.Eval(Context(f.Env(), action, []string{"signup", "register", "login", "contact", "comment", "checkout", "default"}))
			d := scoring.CombineWithFloor(res.Risk, res.Floor, nil, nil, 0, 0, 0, "", "", scoring.DefaultThresholds, scoring.ModeEnforce)
			fired := ids(res.Hits)
			if d.Outcome != c.Expect.Outcome {
				t.Errorf("outcome %s (risk %d), want %s; fired %v", d.Outcome, d.Risk, c.Expect.Outcome, fired)
			}
			if c.Expect.MinRisk != nil && d.Risk < *c.Expect.MinRisk {
				t.Errorf("risk %d < min %d; fired %v", d.Risk, *c.Expect.MinRisk, fired)
			}
			if c.Expect.MaxRisk != nil && d.Risk > *c.Expect.MaxRisk {
				t.Errorf("risk %d > max %d; fired %v", d.Risk, *c.Expect.MaxRisk, fired)
			}
			for _, id := range c.Expect.Fires {
				if !slices.Contains(fired, id) {
					t.Errorf("%s did not fire; fired %v", id, fired)
				}
			}
			for _, id := range c.Expect.NotFires {
				if slices.Contains(fired, id) {
					t.Errorf("%s fired but must not", id)
				}
			}
		})
	}
}
