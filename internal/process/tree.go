package process

// TreeNode represents a node in the process tree
type TreeNode struct {
	Process  *Info       `json:"process"`
	Children []*TreeNode `json:"children,omitempty"`
}

// BuildTree builds a process tree starting from the given root PID
func BuildTree(rootPID int32) (*TreeNode, error) {
	// Get all processes
	procs, err := List()
	if err != nil {
		return nil, err
	}

	// Build lookup maps
	byPID := make(map[int32]*Info)
	byPPID := make(map[int32][]*Info)

	for _, p := range procs {
		byPID[p.PID] = p
		byPPID[p.PPID] = append(byPPID[p.PPID], p)
	}

	// Find root process
	rootProc, exists := byPID[rootPID]
	if !exists {
		// If root doesn't exist, create a placeholder
		rootProc = &Info{
			PID:  rootPID,
			Name: "unknown",
		}
	}

	// Build tree recursively
	return buildNode(rootProc, byPPID), nil
}

func buildNode(proc *Info, byPPID map[int32][]*Info) *TreeNode {
	node := &TreeNode{
		Process: proc,
	}

	// Find children
	children := byPPID[proc.PID]
	for _, child := range children {
		childNode := buildNode(child, byPPID)
		node.Children = append(node.Children, childNode)
	}

	return node
}

// FlattenTree returns all processes in the tree as a flat list
func FlattenTree(root *TreeNode) []*Info {
	var result []*Info
	flattenRecursive(root, &result)
	return result
}

func flattenRecursive(node *TreeNode, result *[]*Info) {
	if node == nil {
		return
	}
	*result = append(*result, node.Process)
	for _, child := range node.Children {
		flattenRecursive(child, result)
	}
}

// FindAncestors returns the ancestor chain for a given PID
func FindAncestors(pid int32) ([]*Info, error) {
	procs, err := List()
	if err != nil {
		return nil, err
	}

	// Build PID lookup
	byPID := make(map[int32]*Info)
	for _, p := range procs {
		byPID[p.PID] = p
	}

	var ancestors []*Info
	current := byPID[pid]

	for current != nil && current.PID != 0 {
		ancestors = append(ancestors, current)
		current = byPID[current.PPID]
	}

	return ancestors, nil
}
