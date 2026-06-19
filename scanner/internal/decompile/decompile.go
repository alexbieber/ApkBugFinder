package decompile

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

type Result struct {
	JadxPath     string
	Dex2JarPath  string
	ManifestPath string
	SourcesPath  string
	ResourcesPath string
}

func CheckRequirements() error {
	tools := []string{"jadx", "d2j-dex2jar"}
	if runtime.GOOS != "windows" {
		tools = append(tools, "grep")
	}
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			return fmt.Errorf("%s is required but not found in PATH", tool)
		}
	}
	return nil
}

func ValidateAPKName(apkPath string) error {
	base := filepath.Base(apkPath)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)
	re := regexp.MustCompile(`^[a-zA-Z0-9_-]*$`)
	if !re.MatchString(name) {
		return fmt.Errorf("APK filename must be alphanumeric with optional _ or - (rename %s)", base)
	}
	return nil
}

func Decompile(apkPath, workDir string) (*Result, error) {
	if err := ValidateAPKName(apkPath); err != nil {
		return nil, err
	}

	apkBase := filepath.Base(apkPath)
	apkName := strings.TrimSuffix(apkBase, filepath.Ext(apkBase))
	outBase := filepath.Join(workDir, apkName)
	dex2jarPath := outBase + ".jar"
	jadxPath := outBase + "_SAST"

	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return nil, err
	}

	// APKHunt: d2j-dex2jar APK -f -o output.jar
	if out, err := exec.Command("d2j-dex2jar", apkPath, "-f", "-o", dex2jarPath).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("d2j-dex2jar failed: %v\n%s", err, string(out))
	}

	// APKHunt: jadx --deobf APK -d output_SAST/
	if out, err := exec.Command("jadx", "--deobf", apkPath, "-d", jadxPath).CombinedOutput(); err != nil {
		// jadx may return non-zero with partial decompilation; continue if output exists
		if _, statErr := os.Stat(jadxPath); statErr != nil {
			return nil, fmt.Errorf("jadx failed: %v\n%s", err, string(out))
		}
	}

	return &Result{
		JadxPath:      jadxPath,
		Dex2JarPath:   dex2jarPath,
		ManifestPath:  filepath.Join(jadxPath, "resources", "AndroidManifest.xml"),
		SourcesPath:   filepath.Join(jadxPath, "sources"),
		ResourcesPath: filepath.Join(jadxPath, "resources"),
	}, nil
}

func WalkFiles(root string, extensions map[string]bool) ([]string, error) {
	var files []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if extensions[filepath.Ext(path)] {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}
