package grep

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Match struct {
	File    string
	Line    int
	Content string
}

type Options struct {
	Patterns        []string
	UseRegex        bool
	CaseInsensitive bool
	FixedStrings    bool
}

func SearchFile(path string, opts Options) ([]Match, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var res []Match
	scanner := bufio.NewScanner(f)
	lineNum := 0

	var regexes []*regexp.Regexp
	if opts.UseRegex || opts.CaseInsensitive {
		for _, p := range opts.Patterns {
			flags := ""
			if opts.CaseInsensitive {
				flags = "(?i)"
			}
			re, err := regexp.Compile(flags + p)
			if err != nil {
				continue
			}
			regexes = append(regexes, re)
		}
	}

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if matchLine(line, opts, regexes) {
			res = append(res, Match{
				File:    path,
				Line:    lineNum,
				Content: strings.TrimSpace(line),
			})
		}
	}
	return res, scanner.Err()
}

func matchLine(line string, opts Options, regexes []*regexp.Regexp) bool {
	if len(opts.Patterns) == 0 {
		return false
	}

	cmpLine := line
	if opts.CaseInsensitive && !opts.UseRegex && !opts.FixedStrings {
		cmpLine = strings.ToLower(line)
	}

	if opts.UseRegex || opts.CaseInsensitive {
		for _, re := range regexes {
			if re.MatchString(line) {
				return true
			}
		}
		return false
	}

	for _, p := range opts.Patterns {
		target := p
		if opts.CaseInsensitive {
			target = strings.ToLower(p)
		}
		if strings.Contains(cmpLine, target) {
			return true
		}
	}
	return false
}

func SearchFiles(files []string, opts Options) []Match {
	var all []Match
	for _, file := range files {
		matches, err := SearchFile(file, opts)
		if err != nil {
			continue
		}
		all = append(all, matches...)
	}
	return all
}

func FormatEvidence(matches []Match, limit int) string {
	if len(matches) == 0 {
		return ""
	}
	if limit <= 0 {
		limit = 8
	}
	var b strings.Builder
	for i, m := range matches {
		if i >= limit {
			b.WriteString(fmt.Sprintf("\n... and %d more", len(matches)-limit))
			break
		}
		rel := filepath.Base(m.File)
		b.WriteString(fmt.Sprintf("%s:%d: %s\n", rel, m.Line, truncate(m.Content, 120)))
	}
	return strings.TrimSpace(b.String())
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func ContainsAny(text string, subs []string, caseInsensitive bool) bool {
	cmp := text
	if caseInsensitive {
		cmp = strings.ToLower(text)
	}
	for _, sub := range subs {
		target := sub
		if caseInsensitive {
			target = strings.ToLower(sub)
		}
		if strings.Contains(cmp, target) {
			return true
		}
	}
	return false
}
