package update

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestForkDistributionReferences(t *testing.T) {
	if Repo != "cazi-cc/komari-agent" {
		t.Fatalf("self-update repository = %q, want cazi-cc/komari-agent", Repo)
	}

	for _, name := range []string{"install.sh", "install.ps1"} {
		content, err := os.ReadFile(filepath.Join("..", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		text := string(content)
		if !strings.Contains(text, "cazi-cc/komari-agent") {
			t.Fatalf("%s does not declare the Cazi agent repository", name)
		}
		for _, forbidden := range []string{
			"github.com/komari-monitor/komari-agent/releases",
			"api.github.com/repos/komari-monitor/komari-agent",
		} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s still contains official distribution reference %q", name, forbidden)
			}
		}
	}
}
