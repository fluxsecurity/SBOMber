package usagegraph

import (
	"encoding/json"
	"fmt"
	"os"
)

// WriteGraph writes a usage graph as stable, human-readable JSON.
func WriteGraph(outputPath string, graph Graph) error {
	data, err := json.MarshalIndent(graph, "", "  ")
	if err != nil {
		return fmt.Errorf("encode usage graph %s: %w", outputPath, err)
	}

	data = append(data, '\n')
	if err := os.WriteFile(outputPath, data, 0o644); err != nil {
		return fmt.Errorf("write usage graph %s: %w", outputPath, err)
	}

	return nil
}
