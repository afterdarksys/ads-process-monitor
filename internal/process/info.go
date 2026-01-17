package process

import (
	"strings"

	"github.com/shirou/gopsutil/v3/process"
)

// Info contains security-relevant process information
type Info struct {
	PID        int32    `json:"pid"`
	PPID       int32    `json:"ppid"`
	Name       string   `json:"name"`
	Username   string   `json:"username"`
	Cmdline    string   `json:"cmdline"`
	Exe        string   `json:"exe"`
	Cwd        string   `json:"cwd"`
	Status     string   `json:"status"`
	CreateTime int64    `json:"create_time"`
	CPUPercent float64  `json:"cpu_percent"`
	MemPercent float32  `json:"mem_percent"`
	NumThreads int32    `json:"num_threads"`
	Suspicious []string `json:"suspicious,omitempty"`
}

// List returns all running processes with security analysis
func List() ([]*Info, error) {
	procs, err := process.Processes()
	if err != nil {
		return nil, err
	}

	result := make([]*Info, 0, len(procs))

	for _, p := range procs {
		info := getProcessInfo(p)
		if info != nil {
			// Analyze for suspicious behavior
			info.Suspicious = analyzeSuspicious(info)
			result = append(result, info)
		}
	}

	return result, nil
}

func getProcessInfo(p *process.Process) *Info {
	info := &Info{
		PID: p.Pid,
	}

	// Get PPID
	if ppid, err := p.Ppid(); err == nil {
		info.PPID = ppid
	}

	// Get name
	if name, err := p.Name(); err == nil {
		info.Name = name
	}

	// Get username
	if username, err := p.Username(); err == nil {
		info.Username = username
	}

	// Get command line
	if cmdline, err := p.Cmdline(); err == nil {
		info.Cmdline = cmdline
	}

	// Get executable path
	if exe, err := p.Exe(); err == nil {
		info.Exe = exe
	}

	// Get current working directory
	if cwd, err := p.Cwd(); err == nil {
		info.Cwd = cwd
	}

	// Get status
	if status, err := p.Status(); err == nil {
		if len(status) > 0 {
			info.Status = status[0]
		}
	}

	// Get create time
	if createTime, err := p.CreateTime(); err == nil {
		info.CreateTime = createTime
	}

	// Get CPU percent
	if cpu, err := p.CPUPercent(); err == nil {
		info.CPUPercent = cpu
	}

	// Get memory percent
	if mem, err := p.MemoryPercent(); err == nil {
		info.MemPercent = mem
	}

	// Get thread count
	if threads, err := p.NumThreads(); err == nil {
		info.NumThreads = threads
	}

	return info
}

// analyzeSuspicious checks for suspicious process characteristics
func analyzeSuspicious(info *Info) []string {
	var suspicious []string

	// Check for suspicious process names
	suspiciousNames := []string{
		"nc", "ncat", "netcat",      // Netcat variants
		"socat",                      // Socket relay
		"curl", "wget",               // Download tools (when unexpected)
		"python", "perl", "ruby",     // Scripting (context dependent)
		"osascript",                  // AppleScript execution
		"base64",                     // Encoding (potential obfuscation)
		"openssl",                    // Crypto (potential C2)
	}

	nameLower := strings.ToLower(info.Name)
	for _, s := range suspiciousNames {
		if nameLower == s {
			suspicious = append(suspicious, "suspicious_binary:"+s)
			break
		}
	}

	// Check for suspicious command line patterns
	cmdLower := strings.ToLower(info.Cmdline)

	// Base64 encoded commands
	if strings.Contains(cmdLower, "base64") && strings.Contains(cmdLower, "-d") {
		suspicious = append(suspicious, "base64_decode_execution")
	}

	// Reverse shell indicators
	if strings.Contains(cmdLower, "/dev/tcp") || strings.Contains(cmdLower, "/dev/udp") {
		suspicious = append(suspicious, "potential_reverse_shell")
	}

	// Hidden file execution
	if strings.Contains(info.Exe, "/.") {
		suspicious = append(suspicious, "hidden_file_execution")
	}

	// Execution from temp directories
	if strings.HasPrefix(info.Exe, "/tmp/") || strings.HasPrefix(info.Exe, "/var/tmp/") {
		suspicious = append(suspicious, "temp_directory_execution")
	}

	// Execution from user Downloads
	if strings.Contains(info.Exe, "/Downloads/") {
		suspicious = append(suspicious, "downloads_directory_execution")
	}

	// Long base64-like strings in cmdline (potential encoded payload)
	if len(info.Cmdline) > 500 && !strings.Contains(info.Cmdline, " ") {
		suspicious = append(suspicious, "long_encoded_argument")
	}

	// Process masquerading (name doesn't match exe)
	if info.Exe != "" && info.Name != "" {
		exeBase := info.Exe
		if idx := strings.LastIndex(info.Exe, "/"); idx >= 0 {
			exeBase = info.Exe[idx+1:]
		}
		if exeBase != info.Name && !strings.HasPrefix(exeBase, info.Name) {
			// Could be masquerading - but many legit reasons too
			// Only flag if exe is from suspicious location
			if strings.HasPrefix(info.Exe, "/tmp/") {
				suspicious = append(suspicious, "potential_masquerading")
			}
		}
	}

	return suspicious
}
