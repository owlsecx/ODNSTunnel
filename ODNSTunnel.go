// ============================================================================
// ODNSTunnel — DNS Tunnel Detector
// Author  : khaled.s.haddad
// Website : owlsec.org
// Language: Go (stdlib only, CGO disabled, static build)
// Category: ONet
// ============================================================================

package main

import (
	"bufio"
	"crypto/md5"
	"encoding/base32"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"math/rand"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---- OWL UI KIT (cyan "owl" house style) — stdlib only. Shared across the suite ----
// CYAN is the primary brand/frame colour; red is reserved for errors and
// CRITICAL/HIGH severities.
const (
	R   = "\033[91m"       // red     — errors / critical
	GRN = "\033[92m"       // green   — success / low
	YLW = "\033[93m"       // yellow  — prompts / warning text
	CY  = "\033[96m"       // cyan    — primary brand & frames
	W   = "\033[97m"       // white   — body text
	B   = "\033[1m"        // bold
	X   = "\033[0m"        // reset
	MG  = "\033[95m"       // magenta — suite name / accents
	BL  = "\033[94m"       // blue    — accents
	DIM = "\033[2m"        // dim     — secondary text
	OR  = "\033[38;5;208m" // orange  — warning markers
	GY  = "\033[90m"       // gray    — muted
	DR  = CY               // legacy alias: former frame colour → cyan
)

var noColor = os.Getenv("NO_COLOR") != "" || !isatty()

func isatty() bool { fi, _ := os.Stdout.Stat(); return (fi.Mode() & os.ModeCharDevice) != 0 }
func col(s string, c ...string) string {
	if noColor {
		return s
	}
	return strings.Join(c, "") + s + X
}
func clear()           { fmt.Print("\033[H\033[2J") }
func line(w int)       { fmt.Println(col(strings.Repeat("─", w), CY)) }
func okMsg(s string)   { fmt.Println("  " + col("[✔] ", GRN+B) + col(s, W)) }
func errMsg(s string)  { fmt.Println("  " + col("[✘] ", R+B) + col(s, R)) }
func warnMsg(s string) { fmt.Println("  " + col("[!] ", OR+B) + col(s, YLW)) }
func info(s string)    { fmt.Println("  " + col("[*] ", CY) + col(s, DIM+W)) }

// banner prints the cyan ANSI-Shadow wordmark and the suite identity block.
func banner() {
	fmt.Println(col(BANNER, CY))
	fmt.Println("  " + col(SUITE+"  ", B+MG) + col("v"+VERSION, YLW))
	fmt.Println("  " + col(SUBLINE, W))
	fmt.Println()
	fmt.Println("  " + col("Developer : ", DIM) + col(AUTHOR, CY) +
		col("   |   Website : ", DIM) + col(WEBSITE, CY))
	fmt.Println(col(strings.Repeat("─", 66), CY))
	fmt.Println()
}
func prompt(label string) string {
	fmt.Print("  " + col("[»] ", YLW) + col(label+": ", W))
	s, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && s == "" {
		fmt.Println()
		os.Exit(0) // stdin closed (Ctrl-D / end of piped input)
	}
	return strings.TrimSpace(s)
}
func pause() {
	fmt.Print(col("\n  [↩] Press Enter to continue...", YLW))
	bufio.NewReader(os.Stdin).ReadString('\n')
}

// sectionHeader prints a ⬡ heading between two cyan rules.
func sectionHeader(s string) {
	fmt.Println(col(strings.Repeat("─", 66), CY))
	fmt.Println("  " + col("⬡  "+s, B+CY))
	fmt.Println(col(strings.Repeat("─", 66), CY))
	fmt.Println()
}

type menuItem struct {
	key, name, desc, clr string
}

// menu renders the ONode-style main menu and returns the raw selection.
func menu(title string, items []menuItem) string {
	clear()
	banner()
	fmt.Println("  " + col("⬡  "+title, B+CY))
	fmt.Println()
	for _, it := range items {
		fmt.Println("  " + col(pad("["+it.key+"]", 4), it.clr) + "  " +
			col(pad(it.name, 32), W) + col("─ "+it.desc, DIM))
	}
	fmt.Println()
	fmt.Println("  " + col(pad("[H]", 4), YLW+B) + "  " + col(pad("Help & Usage", 32), W) + col("─ How to use, every option, CLI flags & examples", DIM))
	fmt.Println("  " + col(pad("[0]", 4), R) + "  " + col(pad("Exit", 32), W) + col("─ Quit "+APPNAME, DIM))
	fmt.Println()
	fmt.Println(col(strings.Repeat("─", 66), CY))
	return prompt("Select option")
}
func pad(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}
func table(headers []string, rows [][]string) {
	w := make([]int, len(headers))
	for i, h := range headers {
		w[i] = len(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if i < len(w) && len(c) > w[i] {
				w[i] = len(c)
			}
		}
	}
	var hb strings.Builder
	for i, h := range headers {
		hb.WriteString(col(pad(h, w[i]), CY+B))
		if i < len(headers)-1 {
			hb.WriteString(col(" │ ", DR))
		}
	}
	fmt.Println("  " + hb.String())
	seg := make([]string, len(w))
	for i := range w {
		seg[i] = strings.Repeat("─", w[i])
	}
	fmt.Println("  " + col(strings.Join(seg, "─┼─"), DR))
	for _, r := range rows {
		var rb strings.Builder
		for i := range headers {
			v := ""
			if i < len(r) {
				v = r[i]
			}
			rb.WriteString(col(pad(v, w[i]), W))
			if i < len(headers)-1 {
				rb.WriteString(col(" │ ", DR))
			}
		}
		fmt.Println("  " + rb.String())
	}
}

const APPNAME = "ODNSTunnel"
const SUITE = "Owl DNS Tunnel Suite"
const TAGLINE = "DNS Tunnel Detector"
const SUBLINE = "Logs · PCAP · Entropy · Encoded Labels · Exfil Volume · Beacons · Grade"
const VERSION = "1.0"
const AUTHOR = "khaled.s.haddad"
const WEBSITE = "owlsec.org"

const BANNER = `
 ██████╗ ██████╗ ███╗   ██╗███████╗████████╗██╗   ██╗███╗   ██╗███╗   ██╗███████╗██╗
██╔═══██╗██╔══██╗████╗  ██║██╔════╝╚══██╔══╝██║   ██║████╗  ██║████╗  ██║██╔════╝██║
██║   ██║██║  ██║██╔██╗ ██║███████╗   ██║   ██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██║
██║   ██║██║  ██║██║╚██╗██║╚════██║   ██║   ██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██║
╚██████╔╝██████╔╝██║ ╚████║███████║   ██║   ╚██████╔╝██║ ╚████║██║ ╚████║███████╗███████╗
 ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚══════╝
`

// ============================================================================
// OWL SHARED CORE  — Finding model, grading, MITRE ATT&CK, 5-format export,
// output engine, and numeric/byte/stat utilities. Stdlib only.
// ============================================================================

// Severity levels used across all OWL v2 tools.
const (
	SevInfo     = "INFO"
	SevLow      = "LOW"
	SevMedium   = "MEDIUM"
	SevHigh     = "HIGH"
	SevCritical = "CRITICAL"
)

// Finding is the universal result record every OWL tool emits.
type Finding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Score       float64  `json:"score"`
	Category    string   `json:"category"`
	Subject     string   `json:"subject"`
	Description string   `json:"description"`
	Evidence    string   `json:"evidence"`
	ATTCK       []string `json:"attck,omitempty"`
	CWE         string   `json:"cwe,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Reference   string   `json:"reference,omitempty"`
}

// Report bundles findings plus run metadata for export.
type Report struct {
	Tool      string            `json:"tool"`
	Tagline   string            `json:"tagline"`
	Target    string            `json:"target"`
	Generated string            `json:"generated"`
	Stats     map[string]string `json:"stats"`
	Profiles  []Profile         `json:"profiles"`
	Findings  []Finding         `json:"findings"`
	Summary   Summary           `json:"summary"`
	Warnings  []string          `json:"warnings,omitempty"`
}

// Summary is the aggregate posture for a run.
type Summary struct {
	Total     int     `json:"total"`
	Critical  int     `json:"critical"`
	High      int     `json:"high"`
	Medium    int     `json:"medium"`
	Low       int     `json:"low"`
	Info      int     `json:"info"`
	RiskScore float64 `json:"risk_score"`
	Grade     string  `json:"grade"`
}

func sevRank(s string) int {
	switch strings.ToUpper(s) {
	case SevCritical:
		return 5
	case SevHigh:
		return 4
	case SevMedium:
		return 3
	case SevLow:
		return 2
	case SevInfo:
		return 1
	}
	return 0
}

func sevWeight(s string) float64 {
	switch strings.ToUpper(s) {
	case SevCritical:
		return 10.0
	case SevHigh:
		return 7.0
	case SevMedium:
		return 4.0
	case SevLow:
		return 1.5
	case SevInfo:
		return 0.2
	}
	return 0.0
}

// summarize computes the aggregate posture and letter grade for a finding set.
func summarize(fs []Finding) Summary {
	var s Summary
	s.Total = len(fs)
	var raw float64
	for _, f := range fs {
		switch strings.ToUpper(f.Severity) {
		case SevCritical:
			s.Critical++
		case SevHigh:
			s.High++
		case SevMedium:
			s.Medium++
		case SevLow:
			s.Low++
		default:
			s.Info++
		}
		raw += sevWeight(f.Severity)
	}
	s.RiskScore = raw
	s.Grade = gradeFor(s)
	return s
}

// gradeFor maps weighted risk to an A+..F posture grade.
func gradeFor(s Summary) string {
	if s.Critical > 0 {
		if s.Critical >= 3 {
			return "F"
		}
		return "E"
	}
	switch {
	case s.High >= 3:
		return "D"
	case s.High >= 1:
		return "C"
	case s.Medium >= 3:
		return "C"
	case s.Medium >= 1:
		return "B"
	case s.Low >= 1:
		return "A"
	default:
		return "A+"
	}
}

func gradeColor(g string) string {
	switch g {
	case "A+", "A":
		return GRN + B
	case "B":
		return GRN
	case "C":
		return YLW
	case "D", "E":
		return R
	case "F":
		return R + B
	}
	return W
}

// ---------------------------------------------------------------------------
// MITRE ATT&CK technique descriptions (curated subset used by OWL tools).
// ---------------------------------------------------------------------------
var attckDB = map[string]string{
	"T1029":     "Scheduled Transfer",
	"T1048.003": "Exfiltration Over Unencrypted Non-C2 Protocol",
	"T1071.004": "Application Layer Protocol: DNS",
	"T1572":     "Protocol Tunneling",
}

func attckName(id string) string {
	if n, ok := attckDB[id]; ok {
		return n
	}
	return id
}

func attckTag(ids []string) string {
	if len(ids) == 0 {
		return ""
	}
	var parts []string
	for _, id := range ids {
		parts = append(parts, id+" ("+attckName(id)+")")
	}
	return strings.Join(parts, ", ")
}

// ---------------------------------------------------------------------------
// Export engine: TXT, MD, JSON, CSV, SARIF 2.1.0
// ---------------------------------------------------------------------------

func buildReport(target string, fs []Finding) Report {
	sort.SliceStable(fs, func(i, j int) bool {
		if sevRank(fs[i].Severity) != sevRank(fs[j].Severity) {
			return sevRank(fs[i].Severity) > sevRank(fs[j].Severity)
		}
		return fs[i].Score > fs[j].Score
	})
	return Report{
		Tool:      APPNAME,
		Tagline:   TAGLINE,
		Target:    target,
		Generated: time.Now().Format(time.RFC3339),
		Findings:  append([]Finding{}, fs...),
		Summary:   summarize(fs),
	}
}

func exportTXT(r Report) string {
	var b strings.Builder
	b.WriteString("================================================================\n")
	b.WriteString(" " + r.Tool + " — " + r.Tagline + "\n")
	b.WriteString(" Author: khaled.s.haddad    Website: owlsec.org\n")
	b.WriteString("================================================================\n")
	b.WriteString("Target     : " + r.Target + "\n")
	b.WriteString("Generated  : " + r.Generated + "\n")
	b.WriteString(fmt.Sprintf("Grade      : %s   RiskScore: %.1f\n", r.Summary.Grade, r.Summary.RiskScore))
	b.WriteString(fmt.Sprintf("Findings   : %d  (C:%d H:%d M:%d L:%d I:%d)\n",
		r.Summary.Total, r.Summary.Critical, r.Summary.High, r.Summary.Medium, r.Summary.Low, r.Summary.Info))
	b.WriteString("----------------------------------------------------------------\n\n")
	if len(r.Stats) > 0 {
		var ks []string
		for k := range r.Stats {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for _, k := range ks {
			b.WriteString(fmt.Sprintf("  %-20s %s\n", k, r.Stats[k]))
		}
		b.WriteString("\n")
	}
	if len(r.Profiles) > 0 {
		b.WriteString("CLIENT → DOMAIN PROFILES (score ≥ 10)\n")
		b.WriteString(fmt.Sprintf("  %-16s %-26s %6s %6s %5s %5s %10s %6s\n", "CLIENT", "DOMAIN", "Q", "SUBS", "LEN", "ENC", "EXFIL", "SCORE"))
		for _, p := range r.Profiles {
			b.WriteString(fmt.Sprintf("  %-16s %-26s %6d %6d %5.0f %4.0f%% %10s %6.1f %s\n", truncStr(p.Src, 16), truncStr(p.Domain, 26), p.Queries, p.UniqueSubs, p.AvgSubLen, p.EncodedFrac*100, humanBytesI(p.ExfilBytes), p.Score, p.Tool))
		}
		b.WriteString("\n")
	}
	for _, w := range r.Warnings {
		b.WriteString("  ! " + w + "\n")
	}
	for i, f := range r.Findings {
		b.WriteString(fmt.Sprintf("[%03d] %-8s %s\n", i+1, f.Severity, f.Title))
		if f.Subject != "" {
			b.WriteString("      Subject    : " + f.Subject + "\n")
		}
		if f.Category != "" {
			b.WriteString("      Category   : " + f.Category + "\n")
		}
		b.WriteString(fmt.Sprintf("      Score      : %.1f\n", f.Score))
		if f.Description != "" {
			b.WriteString("      Description: " + f.Description + "\n")
		}
		if f.Evidence != "" {
			b.WriteString("      Evidence   : " + f.Evidence + "\n")
		}
		if len(f.ATTCK) > 0 {
			b.WriteString("      ATT&CK     : " + attckTag(f.ATTCK) + "\n")
		}
		if f.CWE != "" {
			b.WriteString("      CWE        : " + f.CWE + "\n")
		}
		if f.Remediation != "" {
			b.WriteString("      Remediation: " + f.Remediation + "\n")
		}
		if f.Reference != "" {
			b.WriteString("      Reference  : " + f.Reference + "\n")
		}
		b.WriteString("\n")
	}
	return b.String()
}

func exportMD(r Report) string {
	var b strings.Builder
	b.WriteString("# " + r.Tool + " Report\n\n")
	b.WriteString("*" + r.Tagline + "*\n\n")
	b.WriteString("- **Target:** " + r.Target + "\n")
	b.WriteString("- **Generated:** " + r.Generated + "\n")
	b.WriteString(fmt.Sprintf("- **Grade:** %s (risk score %.1f)\n", r.Summary.Grade, r.Summary.RiskScore))
	b.WriteString(fmt.Sprintf("- **Findings:** %d — Critical %d, High %d, Medium %d, Low %d, Info %d\n\n",
		r.Summary.Total, r.Summary.Critical, r.Summary.High, r.Summary.Medium, r.Summary.Low, r.Summary.Info))
	if len(r.Profiles) > 0 {
		b.WriteString("## Client → domain profiles\n\n| Client | Domain | Queries | Unique subs | Avg len | Encoded | Est. exfil | Score | Note |\n|---|---|---|---|---|---|---|---|---|\n")
		for _, p := range r.Profiles {
			b.WriteString(fmt.Sprintf("| %s | %s | %d | %d | %.0f | %.0f%% | %s | %.1f | %s |\n", p.Src, mdEsc(p.Domain), p.Queries, p.UniqueSubs, p.AvgSubLen, p.EncodedFrac*100, humanBytesI(p.ExfilBytes), p.Score, p.Tool))
		}
		b.WriteString("\n")
	}
	b.WriteString("| # | Severity | Title | Score | ATT&CK |\n")
	b.WriteString("|---|----------|-------|-------|--------|\n")
	for i, f := range r.Findings {
		b.WriteString(fmt.Sprintf("| %d | %s | %s | %.1f | %s |\n",
			i+1, f.Severity, mdEsc(f.Title), f.Score, mdEsc(strings.Join(f.ATTCK, " "))))
	}
	b.WriteString("\n## Details\n\n")
	for i, f := range r.Findings {
		b.WriteString(fmt.Sprintf("### %d. %s (%s)\n\n", i+1, f.Title, f.Severity))
		if f.Subject != "" {
			b.WriteString("- **Subject:** " + mdEsc(f.Subject) + "\n")
		}
		if f.Category != "" {
			b.WriteString("- **Category:** " + mdEsc(f.Category) + "\n")
		}
		b.WriteString(fmt.Sprintf("- **Score:** %.1f\n", f.Score))
		if f.Description != "" {
			b.WriteString("- **Description:** " + mdEsc(f.Description) + "\n")
		}
		if f.Evidence != "" {
			b.WriteString("- **Evidence:** `" + f.Evidence + "`\n")
		}
		if len(f.ATTCK) > 0 {
			b.WriteString("- **ATT&CK:** " + mdEsc(attckTag(f.ATTCK)) + "\n")
		}
		if f.CWE != "" {
			b.WriteString("- **CWE:** " + f.CWE + "\n")
		}
		if f.Remediation != "" {
			b.WriteString("- **Remediation:** " + mdEsc(f.Remediation) + "\n")
		}
		b.WriteString("\n")
	}
	return b.String()
}

func mdEsc(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

func exportJSON(r Report) string {
	buf, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(buf)
}

func exportCSV(r Report) string {
	var sb strings.Builder
	w := csv.NewWriter(&sb)
	w.Write([]string{"id", "severity", "score", "category", "subject", "title", "description", "evidence", "attck", "cwe", "remediation"})
	for _, f := range r.Findings {
		w.Write([]string{f.ID, f.Severity, fmt.Sprintf("%.1f", f.Score), f.Category, f.Subject, f.Title, f.Description, f.Evidence, strings.Join(f.ATTCK, " "), f.CWE, f.Remediation})
	}
	w.Flush()
	return sb.String()
}

func sarifLevel(sev string) string {
	switch strings.ToUpper(sev) {
	case SevCritical, SevHigh:
		return "error"
	case SevMedium:
		return "warning"
	case SevLow, SevInfo:
		return "note"
	}
	return "none"
}

func exportSARIF(r Report) string {
	type sarifMsg struct {
		Text string `json:"text"`
	}
	type sarifRule struct {
		ID               string   `json:"id"`
		Name             string   `json:"name"`
		ShortDescription sarifMsg `json:"shortDescription"`
	}
	type sarifResult struct {
		RuleID  string   `json:"ruleId"`
		Level   string   `json:"level"`
		Message sarifMsg `json:"message"`
	}
	type driver struct {
		Name    string      `json:"name"`
		Version string      `json:"version"`
		Rules   []sarifRule `json:"rules"`
	}
	type tool struct {
		Driver driver `json:"driver"`
	}
	type run struct {
		Tool    tool          `json:"tool"`
		Results []sarifResult `json:"results"`
	}
	type doc struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []run  `json:"runs"`
	}
	seen := map[string]bool{}
	var rules []sarifRule
	var results []sarifResult
	for _, f := range r.Findings {
		rid := f.ID
		if rid == "" {
			rid = "OWL-" + strings.ToUpper(APPNAME)
		}
		if !seen[rid] {
			seen[rid] = true
			rules = append(rules, sarifRule{ID: rid, Name: f.Title, ShortDescription: sarifMsg{Text: f.Title}})
		}
		msg := f.Description
		if f.Evidence != "" {
			msg += " | evidence: " + f.Evidence
		}
		if len(f.ATTCK) > 0 {
			msg += " | ATT&CK: " + strings.Join(f.ATTCK, ",")
		}
		results = append(results, sarifResult{RuleID: rid, Level: sarifLevel(f.Severity), Message: sarifMsg{Text: msg}})
	}
	d := doc{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []run{{
			Tool:    tool{Driver: driver{Name: APPNAME, Version: VERSION, Rules: rules}},
			Results: results,
		}},
	}
	buf, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(buf)
}

func renderReport(format string, r Report) string {
	switch strings.ToLower(format) {
	case "md", "markdown":
		return exportMD(r)
	case "json":
		return exportJSON(r)
	case "csv":
		return exportCSV(r)
	case "sarif":
		return exportSARIF(r)
	default:
		return exportTXT(r)
	}
}

func writeOutput(path, content string) error {
	if path == "" || path == "-" {
		fmt.Print(content)
		if !strings.HasSuffix(content, "\n") {
			fmt.Println()
		}
		return nil
	}
	return os.WriteFile(path, []byte(content), 0644)
}

// ---------------------------------------------------------------------------
// Numeric and console helpers
// ---------------------------------------------------------------------------

func mean(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	var s float64
	for _, x := range xs {
		s += x
	}
	return s / float64(len(xs))
}

func stddev(xs []float64) float64 {
	if len(xs) < 2 {
		return 0
	}
	m := mean(xs)
	var s float64
	for _, x := range xs {
		d := x - m
		s += d * d
	}
	return math.Sqrt(s / float64(len(xs)-1))
}

func maxF(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	m := xs[0]
	for _, x := range xs {
		if x > m {
			m = x
		}
	}
	return m
}

func clampF(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func asciiBar(frac float64, width int) string {
	if frac < 0 {
		frac = 0
	}
	if frac > 1 {
		frac = 1
	}
	fill := int(frac * float64(width))
	return strings.Repeat("█", fill) + strings.Repeat("░", width-fill)
}

func truncStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n < 4 {
		return s[:n]
	}
	return s[:n-3] + "..."
}

func printFindingsTable(fs []Finding) {
	if len(fs) == 0 {
		info("no findings")
		return
	}
	var rows [][]string
	for i, f := range fs {
		rows = append(rows, []string{fmt.Sprintf("%d", i+1), f.Severity, truncStr(f.Title, 48), fmt.Sprintf("%.1f", f.Score), strings.Join(f.ATTCK, " ")})
	}
	table([]string{"#", "SEV", "TITLE", "SCORE", "ATT&CK"}, rows)
}

func printSummary(s Summary) {
	fmt.Println()
	fmt.Println("  " + col("Posture Grade: ", W) + col(s.Grade, gradeColor(s.Grade)+B) +
		col(fmt.Sprintf("   Risk Score: %.1f", s.RiskScore), GY))
	fmt.Printf("  %s C:%d  H:%d  M:%d  L:%d  I:%d\n", col("Findings", DIM),
		s.Critical, s.High, s.Medium, s.Low, s.Info)
}

func kv(k, v string) {
	fmt.Printf("  %s %s\n", col(pad(k+":", 16), DIM), col(v, W))
}

func barChart(labels []string, values []float64, width int) string {
	var b strings.Builder
	maxv := maxF(values)
	if maxv == 0 {
		maxv = 1
	}
	wl := 0
	for _, l := range labels {
		if len(l) > wl {
			wl = len(l)
		}
	}
	for i := range labels {
		if i >= len(values) {
			break
		}
		fmt.Fprintf(&b, "  %s │ %s %.2f\n", pad(labels[i], wl), asciiBar(values[i]/maxv, width), values[i])
	}
	return b.String()
}

// ============================================================================
// ODNSTunnel DOMAIN ENGINE — DNS Tunnel Detector
// Ingests DNS query logs (generic, Zeek TSV/JSON, dnsmasq, BIND, Unbound) and
// packet captures (pcap/pcapng; Ethernet/VLAN, raw IP, Linux SLL/SLL2, NULL;
// IPv4/IPv6; UDP and TCP port 53), pairs responses with their queries, then
// profiles every (client, registered domain) pair: subdomain cardinality and
// length, encoded-label share, character entropy, TXT/NULL use, NXDOMAIN rate,
// estimated exfiltration volume and beacon regularity.
// ============================================================================

type DNSQuery struct {
	Time    time.Time
	HasTime bool
	Src     string
	QName   string
	QType   string
	RCode   string // NOERROR, NXDOMAIN, … ("" = unknown)
	Size    int
}

// ---- log parsing -------------------------------------------------------------

var syslogYear = time.Now().Year()

// parseTS accepts epoch seconds (with fraction), RFC3339, "YYYY-MM-DD HH:MM:SS",
// BIND "02-Jan-2006 15:04:05.000" and syslog "Jan _2 15:04:05" (consumes 1–3 fields).
func parseTS(f []string) (time.Time, int) {
	if len(f) == 0 {
		return time.Time{}, 0
	}
	s := strings.Trim(f[0], "[]")
	if v, err := strconv.ParseFloat(s, 64); err == nil && v > 1e8 && v < 1e11 {
		sec, frac := math.Modf(v)
		return time.Unix(int64(sec), int64(frac*1e9)), 1
	}
	for _, l := range []string{time.RFC3339Nano, "2006-01-02T15:04:05", "02-Jan-2006"} {
		if t, err := time.Parse(l, s); err == nil {
			if l == "02-Jan-2006" && len(f) > 1 {
				if t2, err := time.Parse("02-Jan-2006 15:04:05.000", s+" "+f[1]); err == nil {
					return t2, 2
				}
				if t2, err := time.Parse("02-Jan-2006 15:04:05", s+" "+f[1]); err == nil {
					return t2, 2
				}
			}
			return t, 1
		}
	}
	if len(f) > 1 {
		if t, err := time.Parse("2006-01-02 15:04:05", s+" "+strings.Split(f[1], ".")[0]); err == nil {
			return t, 2
		}
	}
	if len(f) > 2 {
		if t, err := time.Parse("Jan _2 15:04:05 2006", fmt.Sprintf("%s %2s %s %d", s, f[1], f[2], syslogYear)); err == nil {
			return t, 3
		}
	}
	return time.Time{}, 0
}

func normName(n string) string { return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), ".")) }

func looksLikeType(s string) bool {
	s = strings.ToUpper(s)
	if dnsTypeNums[s] != 0 || strings.HasPrefix(s, "TYPE") {
		return true
	}
	return false
}

// parseDNSLog auto-detects the log format line by line.
func parseDNSLog(text string) ([]DNSQuery, string, []string) {
	var out []DNSQuery
	var warns []string
	format := "generic"
	var zeekCols map[string]int
	pending := map[string]int{} // dnsmasq: name → index of last query, for reply rcodes
	bad := 0
	for ln, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		if strings.HasPrefix(t, "#fields") {
			format, zeekCols = "zeek-tsv", map[string]int{}
			for i, c := range strings.Split(t, "\t")[1:] {
				zeekCols[c] = i
			}
			continue
		}
		if strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
			continue
		}
		var q DNSQuery
		ok := false
		switch {
		case zeekCols != nil:
			c := strings.Split(line, "\t")
			get := func(k string) string {
				if i, has := zeekCols[k]; has && i < len(c) && c[i] != "-" && c[i] != "(empty)" {
					return c[i]
				}
				return ""
			}
			if qn := get("query"); qn != "" {
				q = DNSQuery{Src: get("id.orig_h"), QName: normName(qn), QType: strings.ToUpper(get("qtype_name")), RCode: strings.ToUpper(get("rcode_name"))}
				q.Time, _ = parseTS([]string{get("ts")})
				ok = true
			}
		case strings.HasPrefix(t, "{"):
			format = "json"
			var m map[string]interface{}
			if json.Unmarshal([]byte(t), &m) == nil {
				str := func(keys ...string) string {
					for _, k := range keys {
						if v, has := m[k]; has {
							switch x := v.(type) {
							case string:
								return x
							case float64:
								return strconv.FormatFloat(x, 'f', -1, 64)
							}
						}
					}
					return ""
				}
				if qn := str("query", "qname", "question", "domain", "name"); qn != "" {
					q = DNSQuery{Src: str("id.orig_h", "src_ip", "client", "client_ip", "src"), QName: normName(qn),
						QType: strings.ToUpper(str("qtype_name", "qtype", "query_type", "type")), RCode: strings.ToUpper(str("rcode_name", "rcode", "response_code"))}
					q.Time, _ = parseTS([]string{str("ts", "timestamp", "time")})
					ok = true
				}
			}
		case strings.Contains(t, "dnsmasq") && (strings.Contains(t, " query[") || strings.Contains(t, " reply ") || strings.Contains(t, " cached ")):
			format = "dnsmasq"
			f := strings.Fields(t)
			ts, _ := parseTS(f)
			for i, tok := range f {
				if strings.HasPrefix(tok, "query[") && i+3 < len(f) && f[i+2] == "from" {
					q = DNSQuery{Time: ts, Src: f[i+3], QName: normName(f[i+1]), QType: strings.TrimSuffix(strings.TrimPrefix(tok, "query["), "]")}
					ok = true
				}
				if (tok == "reply" || tok == "cached") && i+3 < len(f) && f[i+2] == "is" {
					if idx, has := pending[normName(f[i+1])]; has {
						switch f[i+3] {
						case "NXDOMAIN":
							out[idx].RCode = "NXDOMAIN"
						case "SERVFAIL", "REFUSED":
							out[idx].RCode = f[i+3]
						default:
							if out[idx].RCode == "" {
								out[idx].RCode = "NOERROR"
							}
						}
					}
				}
			}
		case strings.Contains(t, "query: "):
			format = "bind"
			f := strings.Fields(t)
			ts, _ := parseTS(f)
			i := strings.Index(t, "query: ")
			rest := strings.Fields(t[i+7:])
			if len(rest) >= 3 {
				q = DNSQuery{Time: ts, QName: normName(rest[0]), QType: strings.ToUpper(rest[2])}
				for _, tok := range strings.Fields(t[:i]) {
					if h := strings.SplitN(tok, "#", 2); len(h) == 2 && net.ParseIP(h[0]) != nil {
						q.Src = h[0]
					}
				}
				ok = true
			}
		case strings.Contains(t, "unbound[") && strings.Contains(t, " info: "):
			format = "unbound"
			f := strings.Fields(t)
			ts, _ := parseTS(f)
			i := strings.Index(t, " info: ")
			rest := strings.Fields(t[i+7:])
			if len(rest) >= 3 && net.ParseIP(rest[0]) != nil && looksLikeType(rest[2]) {
				q = DNSQuery{Time: ts, Src: rest[0], QName: normName(rest[1]), QType: strings.ToUpper(rest[2])}
				ok = true
			}
		default:
			// generic: [TIMESTAMP] SRC QNAME QTYPE [RCODE] [SIZE]
			f := strings.Fields(t)
			ts, used := parseTS(f)
			f = f[used:]
			if len(f) >= 3 && looksLikeType(f[2]) {
				q = DNSQuery{Time: ts, Src: f[0], QName: normName(f[1]), QType: strings.ToUpper(f[2])}
				if len(f) >= 4 {
					q.RCode = strings.ToUpper(f[3])
				}
				if len(f) >= 5 {
					q.Size, _ = strconv.Atoi(f[4])
				}
				ok = true
			}
		}
		if !ok {
			if format == "generic" || format == "bind" {
				bad++
				if bad <= 5 {
					warns = append(warns, fmt.Sprintf("line %d: unrecognised: %s", ln+1, truncStr(t, 70)))
				}
			}
			continue
		}
		if q.QName == "" {
			continue
		}
		if q.Src == "" {
			q.Src = "unknown"
		}
		if q.QType == "" {
			q.QType = "A"
		}
		q.HasTime = !q.Time.IsZero()
		out = append(out, q)
		pending[q.QName] = len(out) - 1
	}
	if bad > 5 {
		warns = append(warns, fmt.Sprintf("… %d unrecognised lines in total", bad))
	}
	return out, format, warns
}

// ---- packet capture ------------------------------------------------------------

var dnsTypeNums = map[string]int{"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "NULL": 10, "PTR": 12, "HINFO": 13, "MX": 15,
	"TXT": 16, "AAAA": 28, "SRV": 33, "NAPTR": 35, "OPT": 41, "DS": 43, "RRSIG": 46, "DNSKEY": 48, "SVCB": 64,
	"HTTPS": 65, "SPF": 99, "AXFR": 252, "ANY": 255, "CAA": 257, "PRIVATE": 65399}

func dnsTypeName(n int) string {
	for k, v := range dnsTypeNums {
		if v == n && k != "PRIVATE" {
			return k
		}
	}
	if n >= 65280 {
		return "PRIVATE"
	}
	return fmt.Sprintf("TYPE%d", n)
}

func dnsRCodeName(c int) string {
	if s, ok := map[int]string{0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}[c]; ok {
		return s
	}
	return fmt.Sprintf("RCODE%d", c)
}

type capPkt struct {
	ts   time.Time
	link int
	data []byte
}

// readCapture parses classic pcap (both byte orders, µs/ns) and pcapng.
func readCapture(b []byte) ([]capPkt, error) {
	if len(b) < 24 {
		return nil, errors.New("file too small for a capture")
	}
	switch binary.LittleEndian.Uint32(b) {
	case 0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1:
		var bo binary.ByteOrder = binary.LittleEndian
		m := binary.LittleEndian.Uint32(b)
		if m == 0xd4c3b2a1 || m == 0x4d3cb2a1 {
			bo = binary.BigEndian
		}
		nano := m == 0xa1b23c4d || m == 0x4d3cb2a1
		link := int(bo.Uint32(b[20:]))
		var out []capPkt
		for off := 24; off+16 <= len(b); {
			sec, frac := bo.Uint32(b[off:]), bo.Uint32(b[off+4:])
			n := int(bo.Uint32(b[off+8:]))
			off += 16
			if n < 0 || off+n > len(b) {
				break
			}
			ns := int64(frac) * 1000
			if nano {
				ns = int64(frac)
			}
			out = append(out, capPkt{time.Unix(int64(sec), ns), link, b[off : off+n]})
			off += n
		}
		return out, nil
	case 0x0a0d0d0a:
		var out []capPkt
		var bo binary.ByteOrder = binary.LittleEndian
		var links []int
		var tsres []float64
		for off := 0; off+12 <= len(b); {
			if binary.LittleEndian.Uint32(b[off:]) == 0x0a0d0d0a && off+12 <= len(b) {
				if binary.LittleEndian.Uint32(b[off+8:]) == 0x1a2b3c4d {
					bo = binary.LittleEndian
				} else {
					bo = binary.BigEndian
				}
				links, tsres = nil, nil
			}
			typ, blen := bo.Uint32(b[off:]), int(bo.Uint32(b[off+4:]))
			if blen < 12 || off+blen > len(b) {
				break
			}
			body := b[off+8 : off+blen-4]
			switch typ {
			case 1: // IDB
				if len(body) >= 8 {
					links = append(links, int(bo.Uint16(body)))
					res := 1e-6
					for o := 8; o+4 <= len(body); {
						code, l := bo.Uint16(body[o:]), int(bo.Uint16(body[o+2:]))
						if code == 0 || o+4+l > len(body) {
							break
						}
						if code == 9 && l >= 1 {
							v := body[o+4]
							if v&0x80 != 0 {
								res = math.Pow(2, -float64(v&0x7f))
							} else {
								res = math.Pow(10, -float64(v))
							}
						}
						o += 4 + (l+3)&^3
					}
					tsres = append(tsres, res)
				}
			case 6: // EPB
				if len(body) >= 20 {
					iface := int(bo.Uint32(body))
					ts := uint64(bo.Uint32(body[4:]))<<32 | uint64(bo.Uint32(body[8:]))
					cl := int(bo.Uint32(body[12:]))
					if iface < len(links) && 20+cl <= len(body) {
						secs := float64(ts) * tsres[iface]
						out = append(out, capPkt{time.Unix(0, int64(secs*1e9)), links[iface], body[20 : 20+cl]})
					}
				}
			case 3: // SPB
				if len(body) >= 4 && len(links) > 0 {
					out = append(out, capPkt{time.Time{}, links[0], body[4:]})
				}
			}
			off += blen
		}
		return out, nil
	}
	return nil, errors.New("not a pcap/pcapng file")
}

// ipPayload strips the link layer and returns (src, dst, proto, transport payload).
func ipPayload(link int, d []byte) (string, string, int, []byte, bool) {
	switch link {
	case 1: // Ethernet (+ VLAN tags)
		if len(d) < 14 {
			return "", "", 0, nil, false
		}
		et, off := binary.BigEndian.Uint16(d[12:]), 14
		for (et == 0x8100 || et == 0x88a8) && len(d) >= off+4 {
			et, off = binary.BigEndian.Uint16(d[off+2:]), off+4
		}
		if et != 0x0800 && et != 0x86dd {
			return "", "", 0, nil, false
		}
		d = d[off:]
	case 113: // Linux SLL
		if len(d) < 16 {
			return "", "", 0, nil, false
		}
		d = d[16:]
	case 276: // Linux SLL2
		if len(d) < 20 {
			return "", "", 0, nil, false
		}
		d = d[20:]
	case 0, 108: // BSD loopback / NULL
		if len(d) < 4 {
			return "", "", 0, nil, false
		}
		d = d[4:]
	case 101, 12, 14, 228, 229: // raw IP
	default:
		return "", "", 0, nil, false
	}
	if len(d) < 1 {
		return "", "", 0, nil, false
	}
	switch d[0] >> 4 {
	case 4:
		ihl := int(d[0]&0x0f) * 4
		if len(d) < 20 || ihl < 20 || len(d) < ihl {
			return "", "", 0, nil, false
		}
		if binary.BigEndian.Uint16(d[6:])&0x1fff != 0 {
			return "", "", 0, nil, false // non-first fragment
		}
		tl := int(binary.BigEndian.Uint16(d[2:]))
		if tl < ihl || tl > len(d) {
			tl = len(d)
		}
		return net.IP(d[12:16]).String(), net.IP(d[16:20]).String(), int(d[9]), d[ihl:tl], true
	case 6:
		if len(d) < 40 {
			return "", "", 0, nil, false
		}
		nh, off := int(d[6]), 40
		for (nh == 0 || nh == 43 || nh == 60) && len(d) >= off+8 { // hop-by-hop, routing, dest-opts
			nh, off = int(d[off]), off+8+int(d[off+1])*8
		}
		if off > len(d) {
			return "", "", 0, nil, false
		}
		return net.IP(d[8:24]).String(), net.IP(d[24:40]).String(), nh, d[off:], true
	}
	return "", "", 0, nil, false
}

// readDNSName decodes a (possibly compressed) name at off; returns name and
// the offset after the name in the original position.
func readDNSName(b []byte, off int) (string, int, error) {
	var labels []string
	end, hops := -1, 0
	for {
		if off >= len(b) {
			return "", 0, errors.New("truncated name")
		}
		l := int(b[off])
		switch {
		case l == 0:
			if end < 0 {
				end = off + 1
			}
			return strings.Join(labels, "."), end, nil
		case l&0xc0 == 0xc0:
			if off+1 >= len(b) || hops > 30 {
				return "", 0, errors.New("bad compression pointer")
			}
			if end < 0 {
				end = off + 2
			}
			off = int(binary.BigEndian.Uint16(b[off:]) & 0x3fff)
			hops++
		default:
			if off+1+l > len(b) {
				return "", 0, errors.New("label overflow")
			}
			labels = append(labels, string(b[off+1:off+1+l]))
			off += 1 + l
		}
	}
}

type dnsMsg struct {
	id       uint16
	response bool
	rcode    int
	qname    string
	qtype    int
	size     int
}

func parseDNSMsg(b []byte) (dnsMsg, bool) {
	if len(b) < 12 || binary.BigEndian.Uint16(b[4:]) < 1 {
		return dnsMsg{}, false
	}
	if (b[2]>>3)&0x0f != 0 { // only standard queries
		return dnsMsg{}, false
	}
	name, off, err := readDNSName(b, 12)
	if err != nil || off+4 > len(b) {
		return dnsMsg{}, false
	}
	return dnsMsg{id: binary.BigEndian.Uint16(b), response: b[2]&0x80 != 0, rcode: int(b[3] & 0x0f),
		qname: normName(name), qtype: int(binary.BigEndian.Uint16(b[off:])), size: len(b)}, true
}

// extractDNSFromCapture turns packets into queries, attaching each response's
// rcode/size to its query (same client, txid and name). Responses whose query
// was not captured become queries attributed to the client they were sent to.
func extractDNSFromCapture(pkts []capPkt) ([]DNSQuery, int) {
	var out []DNSQuery
	open := map[string]int{}
	tcpMsgs := 0
	for _, p := range pkts {
		src, dst, proto, pl, ok := ipPayload(p.link, p.data)
		if !ok {
			continue
		}
		var sport, dport int
		var msgs [][]byte
		switch proto {
		case 17:
			if len(pl) < 8 {
				continue
			}
			sport, dport = int(binary.BigEndian.Uint16(pl)), int(binary.BigEndian.Uint16(pl[2:]))
			msgs = [][]byte{pl[8:]}
		case 6:
			if len(pl) < 20 {
				continue
			}
			sport, dport = int(binary.BigEndian.Uint16(pl)), int(binary.BigEndian.Uint16(pl[2:]))
			doff := int(pl[12]>>4) * 4
			if doff < 20 || doff > len(pl) {
				continue
			}
			seg := pl[doff:]
			for len(seg) >= 2 { // length-prefixed messages fully inside this segment
				l := int(binary.BigEndian.Uint16(seg))
				if l == 0 || 2+l > len(seg) {
					break
				}
				msgs = append(msgs, seg[2:2+l])
				seg = seg[2+l:]
				tcpMsgs++
			}
		default:
			continue
		}
		if sport != 53 && dport != 53 {
			continue
		}
		for _, raw := range msgs {
			m, ok := parseDNSMsg(raw)
			if !ok {
				continue
			}
			if !m.response {
				key := fmt.Sprintf("%s|%d|%s", src, m.id, m.qname)
				out = append(out, DNSQuery{Time: p.ts, HasTime: !p.ts.IsZero(), Src: src, QName: m.qname, QType: dnsTypeName(m.qtype), Size: m.size})
				open[key] = len(out) - 1
				continue
			}
			key := fmt.Sprintf("%s|%d|%s", dst, m.id, m.qname)
			if i, has := open[key]; has {
				out[i].RCode = dnsRCodeName(m.rcode)
				if m.size > out[i].Size {
					out[i].Size = m.size
				}
				delete(open, key)
			} else {
				out = append(out, DNSQuery{Time: p.ts, HasTime: !p.ts.IsZero(), Src: dst, QName: m.qname, QType: dnsTypeName(m.qtype), RCode: dnsRCodeName(m.rcode), Size: m.size})
			}
		}
	}
	return out, tcpMsgs
}

// ---- features ---------------------------------------------------------------------

var secondLevels = map[string]bool{"co": true, "com": true, "net": true, "org": true, "gov": true, "ac": true,
	"edu": true, "or": true, "ne": true, "go": true, "mil": true, "nom": true, "ltd": true, "plc": true, "sch": true}

// baseDomain returns the registrable domain (eTLD+1, heuristic) and the
// subdomain part to its left.
func baseDomain(name string) (string, string) {
	l := strings.Split(name, ".")
	n := 2
	if len(l) >= 3 && len(l[len(l)-1]) == 2 && secondLevels[l[len(l)-2]] {
		n = 3
	}
	if strings.HasSuffix(name, ".in-addr.arpa") || strings.HasSuffix(name, ".ip6.arpa") {
		n = 2
	}
	if len(l) <= n {
		return name, ""
	}
	return strings.Join(l[len(l)-n:], "."), strings.Join(l[:len(l)-n], ".")
}

// benignEncoded are services whose legitimate queries look like tunnels
// (hash / IP lookups encoded in labels). Hits are reported as INFO only.
var benignEncoded = []string{"in-addr.arpa", "ip6.arpa", "spamhaus.org", "spamcop.net", "surbl.org", "uribl.com",
	"sorbs.net", "barracudacentral.org", "dnswl.org", "mailspike.net", "sophosxl.net", "mcafee.com", "trendmicro.com",
	"senderbase.org", "e5.sk", "cymru.com", "akamaiedge.net", "akamai.net", "cloudfront.net", "amazonaws.com",
	"googlevideo.com", "1e100.net", "gvt1.com", "msedge.net", "trafficmanager.net", "azureedge.net", "fastly.net",
	"edgekey.net", "apple-dns.net", "icloud.com", "local", "lan", "arpa"}

func isBenignEncoded(base string) bool {
	for _, b := range benignEncoded {
		if base == b || strings.HasSuffix(base, "."+b) {
			return true
		}
	}
	return false
}

// encKind classifies one label: "hex", "base32", "base64" or "".
func encKind(s string) string {
	if len(s) < 16 {
		return ""
	}
	hexOK, b32, b64 := true, true, true
	digits := 0
	for _, c := range s {
		lc := c | 0x20
		isHex := (c >= '0' && c <= '9') || (lc >= 'a' && lc <= 'f')
		if !isHex {
			hexOK = false
		}
		if c >= '0' && c <= '9' {
			digits++
		}
		if !((lc >= 'a' && lc <= 'z') || (c >= '0' && c <= '9')) {
			b32 = false
			if c != '-' && c != '_' {
				b64 = false
			}
		}
	}
	switch {
	case hexOK && digits > 0:
		return "hex"
	case b32 && digits > 0 && digits < len(s): // letters + digits, no dictionary-looking runs
		vowels := 0
		for _, c := range strings.ToLower(s) {
			if strings.ContainsRune("aeiou", c) {
				vowels++
			}
		}
		if float64(vowels)/float64(len(s)) < 0.30 {
			return "base32"
		}
	case b64 && digits > 0:
		return "base64"
	}
	return ""
}

func charEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var cnt [256]int
	for i := 0; i < len(s); i++ {
		cnt[s[i]]++
	}
	h := 0.0
	for _, c := range cnt {
		if c > 0 {
			p := float64(c) / float64(len(s))
			h -= p * math.Log2(p)
		}
	}
	return h
}

// Profile is the per (client, registered domain) behaviour summary.
type Profile struct {
	Src         string  `json:"src"`
	Domain      string  `json:"domain"`
	Queries     int     `json:"queries"`
	UniqueSubs  int     `json:"unique_subdomains"`
	AvgSubLen   float64 `json:"avg_subdomain_len"`
	MaxLabel    int     `json:"max_label_len"`
	Entropy     float64 `json:"subdomain_entropy"`
	EncodedFrac float64 `json:"encoded_fraction"`
	Encoding    string  `json:"encoding,omitempty"`
	TXTNull     int     `json:"txt_null_private"`
	NXDomain    int     `json:"nxdomain"`
	Answered    int     `json:"answered"`
	ExfilBytes  int     `json:"est_exfil_bytes"`
	BeaconCV    float64 `json:"beacon_cv,omitempty"`
	BeaconSec   float64 `json:"beacon_interval_s,omitempty"`
	Tool        string  `json:"tool_hint,omitempty"`
	Benign      bool    `json:"known_encoded_service,omitempty"`
	Score       float64 `json:"score"`
	Sample      string  `json:"sample"`
	First, Last time.Time
}

func profileTraffic(qs []DNSQuery) []Profile {
	type acc struct {
		qs   []DNSQuery
		subs map[string]bool
	}
	groups := map[string]*acc{}
	var order []string
	for _, q := range qs {
		base, _ := baseDomain(q.QName)
		k := q.Src + "|" + base
		if groups[k] == nil {
			groups[k] = &acc{subs: map[string]bool{}}
			order = append(order, k)
		}
		groups[k].qs = append(groups[k].qs, q)
	}
	var out []Profile
	for _, k := range order {
		g := groups[k]
		base, _ := baseDomain(g.qs[0].QName)
		p := Profile{Src: g.qs[0].Src, Domain: base, Queries: len(g.qs), Benign: isBenignEncoded(base)}
		var concat strings.Builder
		subLen, labels, encoded := 0, 0, 0
		kinds := map[string]int{}
		var times []time.Time
		for _, q := range g.qs {
			_, sub := baseDomain(q.QName)
			if q.QType == "TXT" || q.QType == "NULL" || q.QType == "PRIVATE" || strings.HasPrefix(q.QType, "TYPE") {
				p.TXTNull++
			}
			switch q.RCode {
			case "NXDOMAIN":
				p.NXDomain++
				p.Answered++
			case "":
			default:
				p.Answered++
			}
			if strings.Contains(q.QName, "dnscat") {
				p.Tool = "dnscat2"
			}
			if q.HasTime {
				times = append(times, q.Time)
			}
			if sub == "" || g.subs[sub] {
				continue
			}
			g.subs[sub] = true
			if p.Sample == "" || len(q.QName) > len(p.Sample) {
				p.Sample = q.QName
			}
			subLen += len(strings.ReplaceAll(sub, ".", ""))
			if concat.Len() < 1<<16 {
				concat.WriteString(strings.ToLower(strings.ReplaceAll(sub, ".", "")))
			}
			for _, lab := range strings.Split(sub, ".") {
				labels++
				if len(lab) > p.MaxLabel {
					p.MaxLabel = len(lab)
				}
				if e := encKind(lab); e != "" {
					encoded++
					kinds[e]++
				}
			}
		}
		p.UniqueSubs = len(g.subs)
		if p.UniqueSubs > 0 {
			p.AvgSubLen = float64(subLen) / float64(p.UniqueSubs)
		}
		if labels > 0 {
			p.EncodedFrac = float64(encoded) / float64(labels)
		}
		best := 0
		for e, n := range kinds {
			if n > best {
				p.Encoding, best = e, n
			}
		}
		p.Entropy = charEntropy(concat.String())
		ratio := map[string]float64{"hex": 0.5, "base32": 0.625, "base64": 0.75}[p.Encoding]
		if ratio == 0 {
			ratio = 0.6
		}
		p.ExfilBytes = int(float64(subLen) * ratio)
		if p.Tool == "" && p.TXTNull*2 > p.Queries && p.Queries >= 10 {
			for _, q := range g.qs {
				if q.QType == "NULL" || q.QType == "PRIVATE" {
					p.Tool = "iodine-like (NULL records)"
					break
				}
			}
		}
		// beaconing: regular inter-query intervals
		if len(times) >= 8 {
			sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
			p.First, p.Last = times[0], times[len(times)-1]
			var d []float64
			for i := 1; i < len(times); i++ {
				d = append(d, times[i].Sub(times[i-1]).Seconds())
			}
			m := mean(d)
			if m >= 1 {
				p.BeaconSec, p.BeaconCV = m, stddev(d)/m
			}
		} else if len(times) > 0 {
			sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
			p.First, p.Last = times[0], times[len(times)-1]
		}
		p.Score = tunnelScore(p)
		out = append(out, p)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out
}

// tunnelScore weighs the features (0..100). Cardinality and label shape carry
// most weight; small samples are damped so a handful of odd lookups cannot
// look like a tunnel.
func tunnelScore(p Profile) float64 {
	if p.Queries == 0 {
		return 0
	}
	s := 0.0
	if p.UniqueSubs >= 5 {
		s += math.Min(22, 5*math.Log2(float64(p.UniqueSubs)/4+1))
	}
	s += math.Min(18, math.Max(0, p.AvgSubLen-12)*0.9)
	s += math.Min(18, p.EncodedFrac*24)
	switch {
	case p.MaxLabel >= 52:
		s += 12
	case p.MaxLabel >= 40:
		s += 8
	case p.MaxLabel >= 30:
		s += 4
	}
	if p.Entropy >= 3.8 && p.AvgSubLen >= 16 {
		s += math.Min(8, (p.Entropy-3.8)*8)
	}
	s += math.Min(12, float64(p.TXTNull)/float64(p.Queries)*16)
	if p.Answered > 0 {
		s += math.Min(6, float64(p.NXDomain)/float64(p.Answered)*8)
	}
	if p.BeaconSec > 0 && p.BeaconCV < 0.3 {
		s += 6
	}
	if p.Tool != "" {
		s += 10
	}
	if p.Queries < 10 {
		s *= float64(p.Queries) / 10
	}
	return math.Round(clampF(s, 0, 100)*10) / 10
}

func humanBytesI(n int) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

func tunnelFindings(profiles []Profile, threshold float64) []Finding {
	var fs []Finding
	for _, p := range profiles {
		desc := fmt.Sprintf("%d queries to %s from %s: %d unique subdomains (avg %.0f chars, longest label %d), %.0f%% encoded-looking labels%s, entropy %.2f bits/char, %d TXT/NULL, %d NXDOMAIN. Estimated data carried in query names: %s.",
			p.Queries, p.Domain, p.Src, p.UniqueSubs, p.AvgSubLen, p.MaxLabel, p.EncodedFrac*100,
			map[bool]string{true: " (" + p.Encoding + ")", false: ""}[p.Encoding != ""], p.Entropy, p.TXTNull, p.NXDomain, humanBytesI(p.ExfilBytes))
		if p.Score >= threshold {
			sev := SevLow
			switch {
			case p.Score >= 70:
				sev = SevHigh
			case p.Score >= 45:
				sev = SevMedium
			}
			if sev == SevHigh && (p.ExfilBytes >= 1<<20 || p.Tool != "") {
				sev = SevCritical
			}
			title := "Possible DNS tunnel"
			if sev == SevHigh || sev == SevCritical {
				title = "DNS tunnel"
			}
			if p.Tool != "" {
				title += " — " + p.Tool
			}
			fix := "Isolate " + p.Src + " and inspect the process making these lookups; sinkhole/block " + p.Domain + " (RPZ) and alert on long, high-entropy query names."
			if p.Benign {
				sev, title = SevInfo, "Encoded lookups to a known reputation/CDN service"
				desc += " The domain is a known service that legitimately encodes data in names (DNSBL, AV cloud lookups, CDN, reverse DNS)."
				fix = "Expected traffic; allow-list if confirmed."
			}
			fs = append(fs, Finding{ID: "DT-TUNNEL", Title: fmt.Sprintf("%s: %s → %s", title, p.Src, p.Domain), Severity: sev,
				Score: p.Score, Category: "dns-tunnel", Subject: p.Src + " → " + p.Domain, Description: desc,
				Evidence: "e.g. " + truncStr(p.Sample, 120), ATTCK: []string{"T1071.004", "T1572", "T1048.003"},
				Remediation: fix, Reference: "SANS: Detecting DNS Tunneling; MITRE T1071.004"})
		}
		if p.BeaconSec > 0 && p.BeaconCV < 0.3 && !p.Benign && p.Queries >= 8 && p.UniqueSubs >= 3 {
			sev := SevMedium
			if p.Score >= 45 {
				sev = SevHigh
			}
			fs = append(fs, Finding{ID: "DT-BEACON", Title: fmt.Sprintf("Regular DNS beacon: %s → %s every %.1fs", p.Src, p.Domain, p.BeaconSec),
				Severity: sev, Score: sevWeight(sev), Category: "dns-tunnel", Subject: p.Src + " → " + p.Domain,
				Description: fmt.Sprintf("%d lookups at a mean interval of %.1fs with a coefficient of variation of %.2f — machine-timed check-ins typical of C2 over DNS.", p.Queries, p.BeaconSec, p.BeaconCV),
				Evidence:    fmt.Sprintf("%s … %s", p.First.Format(time.RFC3339), p.Last.Format(time.RFC3339)),
				ATTCK:       []string{"T1071.004", "T1029"}, Remediation: "Correlate with process/EDR telemetry on " + p.Src + "."})
		}
	}
	if len(fs) == 0 {
		fs = append(fs, Finding{ID: "DT-OK", Title: "No DNS tunneling indicators", Severity: SevInfo,
			Score: sevWeight(SevInfo), Category: "dns-tunnel", Description: "No client/domain pair scored above the threshold."})
	}
	return fs
}

// ---- demo data ------------------------------------------------------------------------

func demoDNSQueries() []DNSQuery {
	var qs []DNSQuery
	base := time.Date(2026, 10, 30, 9, 0, 0, 0, time.UTC)
	add := func(t time.Duration, src, name, typ, rc string) {
		qs = append(qs, DNSQuery{Time: base.Add(t), HasTime: true, Src: src, QName: name, QType: typ, RCode: rc})
	}
	r := rand.New(rand.NewSource(7))
	normal := []string{"www.example.com", "mail.example.com", "cdn.example.com", "api.github.com", "github.com",
		"www.google.com", "fonts.gstatic.com", "outlook.office365.com", "login.microsoftonline.com", "www.bbc.co.uk"}
	for i := 0; i < 120; i++ {
		add(time.Duration(r.Intn(3600))*time.Second, fmt.Sprintf("10.0.0.%d", 10+r.Intn(5)), normal[r.Intn(len(normal))], []string{"A", "AAAA", "HTTPS"}[r.Intn(3)], "NOERROR")
	}
	// CDN + DNSBL lookups that look encoded but are legitimate
	for i := 0; i < 30; i++ {
		add(time.Duration(r.Intn(3600))*time.Second, "10.0.0.12", fmt.Sprintf("rr%d---sn-%x.googlevideo.com", r.Intn(9), r.Int63()), "A", "NOERROR")
		add(time.Duration(r.Intn(3600))*time.Second, "10.0.0.25", fmt.Sprintf("%d.%d.%d.%d.zen.spamhaus.org", r.Intn(255), r.Intn(255), r.Intn(255), r.Intn(255)), "A", "NXDOMAIN")
	}
	// iodine-style: base32 payload in NULL queries, bursty
	for i := 0; i < 160; i++ {
		enc := strings.ToLower(strings.TrimRight(base32.StdEncoding.EncodeToString([]byte(fmt.Sprintf("seq%04d|/etc/shadow chunk %d %x", i, i, r.Int63()))), "="))
		add(time.Duration(600+i)*time.Second, "10.0.0.66", enc[:50]+"."+enc[50:]+".t.tunnel-lab.net", "NULL", "NOERROR")
	}
	// dnscat2-style: hex TXT queries every 5 s
	for i := 0; i < 40; i++ {
		lab := fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("chunk-%d", i))))
		add(time.Duration(1200+i*5)*time.Second, "10.0.0.77", "dnscat."+lab+lab[:10]+".c2-lab.org", "TXT", "NOERROR")
	}
	sort.Slice(qs, func(i, j int) bool { return qs[i].Time.Before(qs[j].Time) })
	return qs
}

// ============================================================================
// Report glue, CLI, demo, self-test, TUI
// ============================================================================

type analysis struct {
	target   string
	format   string
	qs       []DNSQuery
	profiles []Profile
	fs       []Finding
	warns    []string
}

func analyzeQueries(target, format string, qs []DNSQuery, threshold float64, warns []string) *analysis {
	prof := profileTraffic(qs)
	return &analysis{target: target, format: format, qs: qs, profiles: prof, fs: tunnelFindings(prof, threshold), warns: warns}
}

func (a *analysis) report() Report {
	r := buildReport(a.target, append([]Finding{}, a.fs...))
	srcs, doms := map[string]bool{}, map[string]bool{}
	var first, last time.Time
	for _, q := range a.qs {
		srcs[q.Src] = true
		d, _ := baseDomain(q.QName)
		doms[d] = true
		if q.HasTime {
			if first.IsZero() || q.Time.Before(first) {
				first = q.Time
			}
			if q.Time.After(last) {
				last = q.Time
			}
		}
	}
	r.Stats = map[string]string{"input_format": a.format, "queries": strconv.Itoa(len(a.qs)),
		"clients": strconv.Itoa(len(srcs)), "registered_domains": strconv.Itoa(len(doms))}
	if !first.IsZero() {
		r.Stats["time_span"] = last.Sub(first).Round(time.Second).String()
	}
	for i, p := range a.profiles {
		if i >= 25 || p.Score < 10 {
			break
		}
		r.Profiles = append(r.Profiles, p)
	}
	r.Warnings = a.warns
	return r
}

var lastAnalysis *analysis

func loadInput(path string) ([]DNSQuery, string, []string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, "", nil, err
	}
	if pk, err := readCapture(b); err == nil {
		qs, tcp := extractDNSFromCapture(pk)
		var w []string
		if len(qs) == 0 {
			w = append(w, "capture contains no DNS (port 53) traffic")
		}
		if tcp > 0 {
			w = append(w, fmt.Sprintf("%d DNS-over-TCP messages decoded (messages split across segments are skipped)", tcp))
		}
		return qs, "pcap", w, nil
	}
	qs, f, w := parseDNSLog(string(b))
	return qs, f, w, nil
}

var (
	fLog      = flag.String("log", "", "DNS query log file (alias: --input)")
	fInput    = flag.String("input", "", "DNS log or pcap/pcapng file (auto-detected)")
	fPcap     = flag.String("pcap", "", "pcap/pcapng file")
	fThresh   = flag.Float64("threshold", 25, "minimum tunnel score to report")
	fFormat   = flag.String("format", "txt", "report format: txt|md|json|csv|sarif")
	fOutput   = flag.String("output", "", "write to FILE")
	fNoColor  = flag.Bool("no-color", false, "disable ANSI colour")
	fDemo     = flag.Bool("demo", false, "run demonstration")
	fSelfTest = flag.Bool("selftest", false, "run self-tests")
	fVersion  = flag.Bool("version", false, "print version")
)

func usage() {
	banner()
	sec := func(t string) { fmt.Println("  " + col(t, CY+B)) }
	sec("USAGE")
	fmt.Println("    ODNSTunnel [flags]          (no flags → interactive TUI)")
	fmt.Println()
	sec("DESCRIPTION")
	fmt.Println("    Detects DNS tunnelling / exfiltration / C2 in query logs and captures. Every")
	fmt.Println("    (client, registered domain) pair is scored on subdomain cardinality and length,")
	fmt.Println("    encoded-label share, entropy, TXT/NULL use, NXDOMAIN rate and beacon timing.")
	fmt.Println()
	sec("INPUT  (format auto-detected)")
	fmt.Println("    --input FILE      log or pcap/pcapng (--log / --pcap also accepted)")
	fmt.Println("                      logs: Zeek dns.log (TSV/JSON), dnsmasq, BIND, Unbound, JSON lines,")
	fmt.Println("                      generic \"[TIME] SRC QNAME QTYPE [RCODE] [SIZE]\"")
	fmt.Println("                      pcap: Ethernet/VLAN, raw IP, SLL/SLL2; IPv4/IPv6; UDP + TCP/53")
	fmt.Println()
	sec("OPTIONS")
	fmt.Println("    --threshold N     minimum score (0-100) to report (default 25)")
	fmt.Println("    --format FMT      txt|md|json|csv|sarif     --output FILE    --no-color")
	fmt.Println("    --demo  --selftest  --version  -h")
	fmt.Println()
	sec("EXAMPLES")
	fmt.Println("    ODNSTunnel --input /opt/zeek/logs/current/dns.log")
	fmt.Println("    ODNSTunnel --input capture.pcapng --threshold 40")
	fmt.Println("    ODNSTunnel --input /var/log/dnsmasq.log --format json --output dns.json")
	fmt.Println("    ODNSTunnel --input query.log --format sarif --output dns.sarif")
	fmt.Println("    sudo tcpdump -i eth0 -w dns.pcap port 53   # capture, then: --input dns.pcap")
	fmt.Println("    ODNSTunnel --demo")
	fmt.Println()
	fmt.Println("  " + col("ATT&CK", CY+B) + "  T1071.004 DNS · T1572 Protocol Tunneling · T1048.003 Exfiltration · T1029")
	line(66)
}

func main() {
	flag.Usage = usage
	for _, a := range os.Args[1:] {
		if a == "-h" || a == "--help" || a == "help" {
			usage()
			return
		}
	}
	flag.Parse()
	if *fNoColor {
		noColor = true
	}
	in := *fInput
	if in == "" {
		in = *fLog
	}
	if in == "" {
		in = *fPcap
	}
	switch {
	case *fVersion:
		fmt.Printf("%s v%s — %s\n", APPNAME, VERSION, SUITE)
		fmt.Printf("Author : %s\nWebsite: %s\n", AUTHOR, WEBSITE)
		fmt.Println("Build  : Go stdlib, static (CGO disabled)")
	case *fSelfTest:
		if !runSelfTest() {
			os.Exit(1)
		}
	case *fDemo:
		runDemo()
	case in != "":
		qs, f, w, err := loadInput(in)
		if err != nil {
			errMsg(err.Error())
			os.Exit(1)
		}
		if len(qs) == 0 {
			errMsg("no DNS queries found in " + in)
			for _, x := range w {
				warnMsg(x)
			}
			os.Exit(1)
		}
		a := analyzeQueries(in, f, qs, *fThresh, w)
		if err := writeOutput(*fOutput, renderReport(*fFormat, a.report())); err != nil {
			errMsg(err.Error())
			os.Exit(1)
		}
		if a.report().Summary.Critical+a.report().Summary.High > 0 {
			os.Exit(3)
		}
	case len(os.Args) > 1:
		usage()
	default:
		interactive()
	}
}

func printProfiles(ps []Profile, n int) {
	var rows [][]string
	for i, p := range ps {
		if i >= n {
			break
		}
		tag := p.Tool
		if p.Benign {
			tag = "known service"
		}
		rows = append(rows, []string{truncStr(p.Src, 15), truncStr(p.Domain, 24), strconv.Itoa(p.Queries), strconv.Itoa(p.UniqueSubs),
			fmt.Sprintf("%.0f", p.AvgSubLen), fmt.Sprintf("%.0f%%", p.EncodedFrac*100), humanBytesI(p.ExfilBytes), fmt.Sprintf("%.0f", p.Score), tag})
	}
	table([]string{"CLIENT", "DOMAIN", "Q", "SUBS", "LEN", "ENC", "EXFIL", "SCORE", "NOTE"}, rows)
}

func showAnalysis(a *analysis) {
	lastAnalysis = a
	sectionHeader(fmt.Sprintf("Client → domain profiles (%d queries, format %s)", len(a.qs), a.format))
	printProfiles(a.profiles, 15)
	for _, w := range a.warns {
		warnMsg(w)
	}
	fmt.Println()
	sectionHeader("Findings")
	r := a.report()
	printFindingsTable(r.Findings)
	printSummary(r.Summary)
}

func runDemo() {
	a := analyzeQueries("synthetic-demo", "synthetic", demoDNSQueries(), *fThresh, nil)
	if *fOutput == "" && strings.ToLower(*fFormat) != "txt" {
		writeOutput("", renderReport(*fFormat, a.report()))
		return
	}
	banner()
	okMsg("ODNSTunnel demonstration — normal browsing, CDN + DNSBL lookups, an iodine-style NULL tunnel and a dnscat2-style TXT beacon")
	fmt.Println()
	showAnalysis(a)
	if len(a.profiles) > 0 {
		fmt.Println()
		sectionHeader("Score breakdown — " + a.profiles[0].Src + " → " + a.profiles[0].Domain)
		fmt.Print(scoreBreakdown(a.profiles[0]))
	}
	if *fOutput != "" {
		writeOutput(*fOutput, renderReport(*fFormat, a.report()))
	}
}

func scoreBreakdown(p Profile) string {
	var b strings.Builder
	row := func(k, v string) { fmt.Fprintf(&b, "  %-26s %s\n", k, v) }
	row("unique subdomains", strconv.Itoa(p.UniqueSubs))
	row("avg subdomain length", fmt.Sprintf("%.1f chars", p.AvgSubLen))
	row("longest label", strconv.Itoa(p.MaxLabel))
	row("encoded-looking labels", fmt.Sprintf("%.0f%% %s", p.EncodedFrac*100, p.Encoding))
	row("character entropy", fmt.Sprintf("%.2f bits/char", p.Entropy))
	row("TXT/NULL/private queries", fmt.Sprintf("%d of %d", p.TXTNull, p.Queries))
	row("NXDOMAIN", fmt.Sprintf("%d of %d answered", p.NXDomain, p.Answered))
	if p.BeaconSec > 0 {
		row("timing", fmt.Sprintf("every %.1fs, CV %.2f", p.BeaconSec, p.BeaconCV))
	}
	row("est. bytes in names", humanBytesI(p.ExfilBytes))
	if p.Tool != "" {
		row("tool fingerprint", p.Tool)
	}
	row("SCORE", fmt.Sprintf("%.1f / 100", p.Score))
	return b.String()
}

// ---- self-test -------------------------------------------------------------------------

func buildDNSMsg(id uint16, resp bool, rcode int, name string, qtype int) []byte {
	m := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	if resp {
		m[2], m[3] = 0x81, 0x80|byte(rcode)
	}
	for _, l := range strings.Split(name, ".") {
		m = append(m, byte(len(l)))
		m = append(m, l...)
	}
	return append(m, 0, byte(qtype>>8), byte(qtype), 0, 1)
}

func ipv4UDP(src, dst string, sp, dp int, pl []byte) []byte {
	udp := append([]byte{byte(sp >> 8), byte(sp), byte(dp >> 8), byte(dp), byte((8 + len(pl)) >> 8), byte(8 + len(pl)), 0, 0}, pl...)
	ip := []byte{0x45, 0, byte((20 + len(udp)) >> 8), byte(20 + len(udp)), 0, 0, 0, 0, 64, 17, 0, 0}
	ip = append(ip, net.ParseIP(src).To4()...)
	ip = append(ip, net.ParseIP(dst).To4()...)
	return append(ip, udp...)
}

func runSelfTest() bool {
	banner()
	pass, fail := 0, 0
	check := func(n string, ok bool, got string) {
		if ok {
			okMsg(n)
			pass++
		} else {
			errMsg(n + "  →  " + got)
			fail++
		}
	}
	// log formats
	type lc struct{ name, text, src, qname, qtype, rcode string }
	for _, c := range []lc{
		{"generic with epoch timestamp", "1730275200.25 10.1.1.1 WWW.Example.com. A NXDOMAIN 90", "10.1.1.1", "www.example.com", "A", "NXDOMAIN"},
		{"Zeek TSV", "#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tquery\tqtype_name\trcode_name\n1730275200.1\tC1\t10.2.2.2\t5353\tfoo.example.org\tTXT\tNOERROR", "10.2.2.2", "foo.example.org", "TXT", "NOERROR"},
		{"Zeek JSON", `{"ts":1730275200.5,"id.orig_h":"10.3.3.3","query":"a.b.c.net","qtype_name":"AAAA","rcode_name":"NXDOMAIN"}`, "10.3.3.3", "a.b.c.net", "AAAA", "NXDOMAIN"},
		{"dnsmasq + reply rcode", "Oct 30 10:00:01 gw dnsmasq[811]: query[A] x.evil.net from 192.168.1.9\nOct 30 10:00:01 gw dnsmasq[811]: reply x.evil.net is NXDOMAIN", "192.168.1.9", "x.evil.net", "A", "NXDOMAIN"},
		{"BIND query log", "30-Oct-2026 10:00:01.123 client @0x7f 10.4.4.4#41000 (q.example.com): query: q.example.com IN MX +E(0) (10.0.0.1)", "10.4.4.4", "q.example.com", "MX", ""},
		{"Unbound log-queries", "[1730275200] unbound[812:0] info: 10.5.5.5 z.example.com. TXT IN", "10.5.5.5", "z.example.com", "TXT", ""},
	} {
		qs, _, _ := parseDNSLog(c.text)
		ok := len(qs) == 1 && qs[0].Src == c.src && qs[0].QName == c.qname && qs[0].QType == c.qtype && qs[0].RCode == c.rcode
		got := fmt.Sprint(qs)
		if c.name != "BIND query log" && len(qs) == 1 {
			ok = ok && qs[0].HasTime
		}
		check("log: "+c.name, ok, got)
	}
	// capture: classic pcap, Ethernet/IPv4 query + NXDOMAIN response, then raw IPv6 and SLL
	eth := func(ip []byte) []byte { return append(make([]byte, 12), append([]byte{0x08, 0x00}, ip...)...) }
	q := ipv4UDP("10.9.9.9", "10.0.0.1", 40000, 53, buildDNSMsg(0x1234, false, 0, "abc.tunnel.example", 16))
	r := ipv4UDP("10.0.0.1", "10.9.9.9", 53, 40000, buildDNSMsg(0x1234, true, 3, "abc.tunnel.example", 16))
	pc := []byte{0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0}
	for i, p := range [][]byte{eth(q), eth(r)} {
		h := make([]byte, 16)
		binary.LittleEndian.PutUint32(h, uint32(1730275200+i))
		binary.LittleEndian.PutUint32(h[8:], uint32(len(p)))
		binary.LittleEndian.PutUint32(h[12:], uint32(len(p)))
		pc = append(append(pc, h...), p...)
	}
	pk, err := readCapture(pc)
	qs, _ := extractDNSFromCapture(pk)
	check("pcap: query paired with its NXDOMAIN response", err == nil && len(qs) == 1 && qs[0].Src == "10.9.9.9" && qs[0].RCode == "NXDOMAIN" && qs[0].QType == "TXT", fmt.Sprint(err, qs))
	v6 := buildDNSMsg(7, false, 0, "x.y.example", 1)
	udp6 := append([]byte{0x9c, 0x40, 0, 53, 0, byte(8 + len(v6)), 0, 0}, v6...)
	ip6 := append([]byte{0x60, 0, 0, 0, 0, byte(len(udp6)), 17, 64}, append(net.ParseIP("2001:db8::5").To16(), net.ParseIP("2001:db8::53").To16()...)...)
	_, _, _, pl, ok := ipPayload(101, append(ip6, udp6...))
	check("raw IPv6/UDP decoded", ok && len(pl) == len(udp6), "")
	sll := append(make([]byte, 16), q...)
	src, _, proto, _, ok := ipPayload(113, sll)
	check("Linux SLL decoded", ok && src == "10.9.9.9" && proto == 17, src)
	// features
	b, s := baseDomain("a.b.shop.example.co.uk")
	check("registered domain (co.uk)", b == "example.co.uk" && s == "a.b.shop", b+" / "+s)
	check("encoded label: hex", encKind("8f3a9c0e7d6b5a4f3e2d1c0b") == "hex", encKind("8f3a9c0e7d6b5a4f3e2d1c0b"))
	check("encoded label: base32", encKind("mzxw6ytboi2dqnrvgq3tmmbs") == "base32", encKind("mzxw6ytboi2dqnrvgq3tmmbs"))
	check("dictionary label not encoded", encKind("documentation-server") == "", encKind("documentation-server"))
	// end-to-end on the demo
	a := analyzeQueries("t", "synthetic", demoDNSQueries(), 25, nil)
	by := map[string]Profile{}
	for _, p := range a.profiles {
		by[p.Src+"|"+p.Domain] = p
	}
	io := by["10.0.0.66|tunnel-lab.net"]
	check("iodine-style tunnel scored high", io.Score >= 70 && io.Tool != "", fmt.Sprintf("%.1f %q", io.Score, io.Tool))
	dc := by["10.0.0.77|c2-lab.org"]
	check("dnscat2 fingerprint + 5 s beacon", dc.Tool == "dnscat2" && dc.BeaconSec > 4 && dc.BeaconCV < 0.1, fmt.Sprintf("%q %.1f %.2f", dc.Tool, dc.BeaconSec, dc.BeaconCV))
	noisy := 0
	for _, f := range a.fs {
		if f.Severity != SevInfo && !strings.Contains(f.Subject, "tunnel-lab.net") && !strings.Contains(f.Subject, "c2-lab.org") {
			noisy++
		}
	}
	check("normal browsing, CDN and DNSBL not alerted", noisy == 0, strconv.Itoa(noisy))
	check("CDN/DNSBL marked as known encoded service", by["10.0.0.25|spamhaus.org"].Benign, "")
	fmt.Println()
	if fail == 0 {
		okMsg(fmt.Sprintf("all %d self-tests passed", pass))
	} else {
		errMsg(fmt.Sprintf("%d passed, %d failed", pass, fail))
	}
	return fail == 0
}

// ---- interactive TUI ------------------------------------------------------------------

func needLast() bool {
	if lastAnalysis == nil {
		warnMsg("analyse a file (or run the demo) first")
		pause()
		return false
	}
	return true
}

var tuiActions = []struct {
	name, desc string
	run        func()
}{
	{"Analyse a log or capture", "Zeek / dnsmasq / BIND / Unbound / pcap", func() {
		p := prompt("file")
		qs, f, w, err := loadInput(p)
		if err != nil || len(qs) == 0 {
			errMsg(fmt.Sprint("no DNS queries loaded ", err))
			for _, x := range w {
				warnMsg(x)
			}
			pause()
			return
		}
		thr := 25.0
		if v, err := strconv.ParseFloat(prompt("score threshold (blank = 25)"), 64); err == nil {
			thr = v
		}
		showAnalysis(analyzeQueries(p, f, qs, thr, w))
		pause()
	}},
	{"Run synthetic demo", "Tunnel + beacon among normal traffic", func() { runDemo(); pause() }},
	{"Score breakdown", "Feature-by-feature view of a profile", func() {
		if !needLast() {
			return
		}
		printProfiles(lastAnalysis.profiles, 15)
		n, _ := strconv.Atoi(prompt("row number (1 = top)"))
		if n < 1 || n > len(lastAnalysis.profiles) {
			n = 1
		}
		p := lastAnalysis.profiles[n-1]
		sectionHeader(p.Src + " → " + p.Domain)
		fmt.Print(scoreBreakdown(p))
		pause()
	}},
	{"Query volume timeline", "Queries per minute, last analysis", func() {
		if !needLast() {
			return
		}
		sectionHeader("Queries per minute")
		fmt.Print(volumeHistogram(lastAnalysis.qs, 60))
		pause()
	}},
	{"Top domains & query types", "Volume by registered domain / qtype", func() {
		if !needLast() {
			return
		}
		sectionHeader("Top registered domains")
		dom, qt := map[string]float64{}, map[string]float64{}
		for _, q := range lastAnalysis.qs {
			d, _ := baseDomain(q.QName)
			dom[d]++
			qt[q.QType]++
		}
		top := func(m map[string]float64, n int) ([]string, []float64) {
			type kv struct {
				k string
				v float64
			}
			var l []kv
			for k, v := range m {
				l = append(l, kv{k, v})
			}
			sort.Slice(l, func(i, j int) bool { return l[i].v > l[j].v || l[i].v == l[j].v && l[i].k < l[j].k })
			var ks []string
			var vs []float64
			for i, x := range l {
				if i >= n {
					break
				}
				ks, vs = append(ks, x.k), append(vs, x.v)
			}
			return ks, vs
		}
		ks, vs := top(dom, 12)
		fmt.Print(barChart(ks, vs, 40))
		fmt.Println()
		sectionHeader("Query types")
		ks, vs = top(qt, 10)
		fmt.Print(barChart(ks, vs, 40))
		pause()
	}},
	{"Explain the scoring", "What each feature contributes", func() {
		sectionHeader("Scoring model (per client → registered domain)")
		for _, s := range []string{
			"unique subdomains (log-scaled)           up to 22",
			"average subdomain length beyond 12 chars up to 18",
			"share of hex/base32/base64-looking labels up to 18",
			"longest label ≥30 / ≥40 / ≥52 chars      4 / 8 / 12",
			"character entropy (long names only)      up to 8",
			"TXT / NULL / private-type share          up to 12",
			"NXDOMAIN share of answered queries       up to 6",
			"regular beacon timing (CV < 0.3)         6",
			"tool fingerprint (dnscat2, iodine-like)  10",
			"fewer than 10 queries → score scaled down proportionally",
			"≥70 tunnel (CRITICAL with a tool hint or ≥1 MiB carried) · ≥45 MEDIUM · ≥25 LOW",
			"known encoded services (DNSBL, AV cloud, CDNs, reverse DNS) → INFO",
		} {
			bulletLine(s)
		}
		pause()
	}},
	{"Export last report", "txt / md / json / csv / sarif", func() {
		if !needLast() {
			return
		}
		f := prompt("format txt/md/json/csv/sarif")
		if f == "" {
			f = "txt"
		}
		if err := writeOutput(prompt("output file (blank = screen)"), renderReport(f, lastAnalysis.report())); err != nil {
			errMsg(err.Error())
		}
		pause()
	}},
	{"Self-test", "Parser, capture and detector checks", func() { runSelfTest(); pause() }},
}

func bulletLine(s string) { fmt.Println("   " + col("•", CY) + " " + col(s, W)) }

func interactive() {
	for {
		items := make([]menuItem, len(tuiActions))
		for i, a := range tuiActions {
			items[i] = menuItem{key: fmt.Sprintf("%02d", i+1), name: a.name, desc: a.desc, clr: CY + B}
		}
		choice := strings.TrimSpace(menu(TAGLINE, items))
		if choice == "0" || choice == "00" || strings.EqualFold(choice, "q") || strings.EqualFold(choice, "exit") {
			clear()
			banner()
			okMsg("Session closed.")
			return
		}
		if strings.EqualFold(choice, "h") || strings.EqualFold(choice, "help") || choice == "?" {
			tuiHelp()
			continue
		}
		n, err := strconv.Atoi(choice)
		if err != nil || n < 1 || n > len(tuiActions) {
			if choice != "" {
				warnMsg("unknown selection")
				pause()
			}
			continue
		}
		clear()
		banner()
		tuiActions[n-1].run()
	}
}

func volumeHistogram(qs []DNSQuery, bucketSec int) string {
	counts := map[int64]float64{}
	var keys []int64
	for _, q := range qs {
		if !q.HasTime {
			continue
		}
		k := q.Time.Unix() / int64(bucketSec)
		if _, ok := counts[k]; !ok {
			keys = append(keys, k)
		}
		counts[k]++
	}
	if len(keys) == 0 {
		return "  (no timestamps in this input)\n"
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	if len(keys) > 30 {
		keys = keys[len(keys)-30:]
	}
	labs, vals := make([]string, len(keys)), make([]float64, len(keys))
	for i, k := range keys {
		labs[i], vals[i] = time.Unix(k*int64(bucketSec), 0).UTC().Format("15:04"), counts[k]
	}
	return barChart(labs, vals, 40)
}

// ---------------------------------------------------------------------------
// Help & Usage  (interactive menu [H])
// Page 1: in-app guide (what the tool does, every menu option, tips).
// Page 2: the full command-line reference (same text as --help).
// ---------------------------------------------------------------------------

type owlHelpItem struct{ key, text string }

func owlHelpWrap(s string, width int) []string {
	var out []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		if len(words) == 0 {
			out = append(out, "")
			continue
		}
		cur := ""
		for _, w := range words {
			if cur != "" && len([]rune(cur))+1+len([]rune(w)) > width {
				out = append(out, cur)
				cur = w
			} else if cur == "" {
				cur = w
			} else {
				cur += " " + w
			}
		}
		out = append(out, cur)
	}
	return out
}

func owlHelpTitle(t string) {
	fmt.Println()
	fmt.Println("  " + col("▸ "+t, B+CY))
}

func owlHelpPara(lines []string) {
	for _, l := range lines {
		for _, w := range owlHelpWrap(l, 60) {
			fmt.Println("    " + col(w, W))
		}
	}
}

func owlHelpRows(items []owlHelpItem) {
	kw := 0
	for _, it := range items {
		if n := len([]rune(it.key)); n > kw {
			kw = n
		}
	}
	for _, it := range items {
		k := "[" + it.key + "]" + strings.Repeat(" ", kw-len([]rune(it.key)))
		for i, w := range owlHelpWrap(it.text, 56-kw) {
			if i == 0 {
				fmt.Println("    " + col(k, YLW+B) + "  " + col(w, W))
			} else {
				fmt.Println("    " + strings.Repeat(" ", kw+2) + "  " + col(w, W))
			}
		}
	}
}

func owlHelpRule() { fmt.Println(col(strings.Repeat("─", 66), CY)) }

func tuiHelp() {
	clear()
	banner()
	owlHelpRule()
	fmt.Println("  " + col("⬡  Help & Usage — "+APPNAME, B+CY))
	owlHelpRule()
	owlHelpTitle("WHAT IT DOES")
	owlHelpPara(owlHelpAbout)
	owlHelpTitle("HOW TO USE THE MENU")
	owlHelpPara(owlHelpFlow)
	owlHelpTitle("MENU OPTIONS")
	owlHelpRows(owlHelpMenu)
	owlHelpTitle("TIPS")
	owlHelpRows(owlHelpTips)
	fmt.Println()
	owlHelpRule()
	fmt.Println("  " + col("Next page: command-line flags & copy-paste examples", DIM))
	pause()
	clear()
	owlHelpCLI()
	fmt.Println()
	fmt.Println("  " + col("Tip: the same reference is printed by  "+APPNAME+" --help", DIM))
	pause()
}

var owlHelpAbout = []string{
	"ODNSTunnel finds DNS tunnelling, data exfiltration over DNS and DNS-based C2 (tools such as iodine, dnscat2 and DNS beacons). It groups every query by client and registered domain (e.g. 10.0.0.5 → evil.com) and scores each pair from 0 to 100.",
	"The score uses the number of unique subdomains, label length, base32/base64/hex-looking labels, entropy, TXT/NULL record use, the NXDOMAIN rate and regular beacon timing. Pairs above the threshold are reported with a grade and MITRE ATT&CK mapping.",
	"It reads Zeek dns.log (TSV or JSON), dnsmasq, BIND and Unbound query logs, JSON lines, and pcap / pcapng captures. The format is detected automatically.",
}

var owlHelpFlow = []string{
	"Type the number of an option (1 or 01) and press Enter. Start with [01] and give it a log or capture, or try [02] to see a full example. Options [03], [04], [05] and [07] then work on that last analysis. [H] opens this help, [0] or q quits.",
}

var owlHelpMenu = []owlHelpItem{
	{"01", "Analyse a log or capture: enter the file path, then the minimum score to report (0-100, blank = 25). Lower it to see more borderline traffic. Shows the ranked suspicious client/domain pairs and findings."},
	{"02", "Run synthetic demo: a tunnel and a beacon hidden among normal traffic, so you can see what a detection looks like."},
	{"03", "Score breakdown: shows the ranked list, then enter a row number (1 = top) to see how much each feature contributed to that pair's score."},
	{"04", "Query volume timeline: queries per minute. Tunnels show steady high volume, beacons show regular spikes."},
	{"05", "Top domains & query types: which registered domains and record types (A, AAAA, TXT, NULL ...) had the most queries."},
	{"06", "Explain the scoring: what each feature measures and why it points to tunnelling."},
	{"07", "Export last report: choose txt, md, json, csv or sarif and an output file (blank = print to screen)."},
	{"08", "Self-test: parser, capture and detector checks."},
}

var owlHelpTips = []owlHelpItem{
	{"*", "CDNs, antivirus and anti-spam lookups (long random-looking names) can score high too. Check the domain before treating it as an incident."},
	{"*", "A capture taken on the resolver or the gateway sees all clients. A capture on a single host sees only that host."},
	{"*", "Use --format sarif to send the results to a SIEM or code-scanning dashboard."},
}

func owlHelpCLI() { usage() }
