package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/afterdarksystems/ads-process-monitor/internal/process"
	"github.com/spf13/cobra"
)

var treeRoot int32

var treeCmd = &cobra.Command{
	Use:   "tree",
	Short: "Display process tree",
	Long:  `Display process hierarchy as a tree, useful for tracing process chains.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		tree, err := process.BuildTree(treeRoot)
		if err != nil {
			return fmt.Errorf("failed to build process tree: %w", err)
		}

		if outputJSON {
			return outputJSONTree(tree)
		}

		return outputTreeText(tree, 0)
	},
}

func outputJSONTree(tree *process.TreeNode) error {
	output := map[string]interface{}{
		"version": Version,
		"tree":    tree,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}

func outputTreeText(node *process.TreeNode, depth int) error {
	if node == nil {
		return nil
	}

	indent := ""
	for i := 0; i < depth; i++ {
		indent += "  "
	}

	prefix := "├─"
	if depth == 0 {
		prefix = ""
	}

	suspicious := ""
	if len(node.Process.Suspicious) > 0 {
		suspicious = " ⚠️"
	}

	fmt.Printf("%s%s[%d] %s (%s)%s\n",
		indent, prefix, node.Process.PID, node.Process.Name,
		node.Process.Username, suspicious)

	for _, child := range node.Children {
		outputTreeText(child, depth+1)
	}

	return nil
}

func init() {
	rootCmd.AddCommand(treeCmd)
	treeCmd.Flags().Int32VarP(&treeRoot, "pid", "p", 1, "Root PID for tree (default: 1/launchd)")
}
