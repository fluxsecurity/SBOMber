package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	treesitter "github.com/tree-sitter/go-tree-sitter"
	javascript "github.com/tree-sitter/tree-sitter-javascript/bindings/go"
)

type rssSample struct {
	Iteration int   `json:"iteration"`
	RSSKB     int64 `json:"rssKB"`
}

type report struct {
	Mode              string      `json:"mode"`
	Fixture           string      `json:"fixture"`
	SourceBytes       int         `json:"sourceBytes"`
	Repeats           int         `json:"repeats"`
	SampleEvery       int         `json:"sampleEvery"`
	SetLanguageOK     bool        `json:"setLanguageOK"`
	ParseErrors       int         `json:"parseErrors"`
	Samples           []rssSample `json:"samples"`
	InitialRSSKB      int64       `json:"initialRSSKB"`
	FinalRSSKB        int64       `json:"finalRSSKB"`
	DeltaRSSKB        int64       `json:"deltaRSSKB"`
	PeakRSSKB         int64       `json:"peakRSSKB"`
	ElapsedMillis     int64       `json:"elapsedMillis"`
	RetainedTreeCount int         `json:"retainedTreeCount"`
}

func readRSSKB() (int64, error) {
	file, err := os.Open("/proc/self/status")
	if err != nil {
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())

		if len(fields) >= 2 && fields[0] == "VmRSS:" {
			value, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				return 0, err
			}

			return value, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return 0, err
	}

	return 0, fmt.Errorf("VmRSS was not found in /proc/self/status")
}

func sampleRSS(iteration int) (rssSample, error) {
	runtime.GC()
	debug.FreeOSMemory()

	value, err := readRSSKB()
	if err != nil {
		return rssSample{}, err
	}

	return rssSample{
		Iteration: iteration,
		RSSKB:     value,
	}, nil
}

func main() {
	repeats := flag.Int("repeat", 5000, "number of parses")
	sampleEvery := flag.Int("rss-sample", 500, "RSS sampling interval")
	leak := flag.Bool("leak", false, "retain trees without calling Close")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintln(
			os.Stderr,
			"usage: t5bench [--repeat N] [--rss-sample N] [--leak] <fixture>",
		)
		os.Exit(2)
	}

	if *repeats <= 0 || *sampleEvery <= 0 {
		fmt.Fprintln(os.Stderr, "repeat and rss-sample must be positive")
		os.Exit(2)
	}

	fixture := flag.Arg(0)

	source, err := os.ReadFile(fixture)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read fixture:", err)
		os.Exit(1)
	}

	language := treesitter.NewLanguage(javascript.Language())
	if language == nil {
		fmt.Fprintln(os.Stderr, "language creation returned nil")
		os.Exit(1)
	}

	parser := treesitter.NewParser()
	if parser == nil {
		fmt.Fprintln(os.Stderr, "parser creation returned nil")
		os.Exit(1)
	}
	defer parser.Close()

	if err := parser.SetLanguage(language); err != nil {
		fmt.Fprintln(os.Stderr, "set language:", err)
		os.Exit(1)
	}

	result := report{
		Mode:          "close",
		Fixture:       fixture,
		SourceBytes:   len(source),
		Repeats:       *repeats,
		SampleEvery:   *sampleEvery,
		SetLanguageOK: true,
		Samples:       make([]rssSample, 0, *repeats / *sampleEvery + 2),
	}

	if *leak {
		result.Mode = "deliberate-leak"
	}

	initial, err := sampleRSS(0)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sample initial RSS:", err)
		os.Exit(1)
	}

	result.Samples = append(result.Samples, initial)
	result.InitialRSSKB = initial.RSSKB
	result.PeakRSSKB = initial.RSSKB

	retained := make([]*treesitter.Tree, 0)
	started := time.Now()

	for iteration := 1; iteration <= *repeats; iteration++ {
		tree := parser.Parse(source, nil)
		if tree == nil {
			result.ParseErrors++
			continue
		}

		if tree.RootNode().HasError() {
			result.ParseErrors++
		}

		if *leak {
			retained = append(retained, tree)
		} else {
			tree.Close()
		}

		if iteration%*sampleEvery == 0 {
			sample, err := sampleRSS(iteration)
			if err != nil {
				fmt.Fprintln(os.Stderr, "sample RSS:", err)
				os.Exit(1)
			}

			result.Samples = append(result.Samples, sample)

			if sample.RSSKB > result.PeakRSSKB {
				result.PeakRSSKB = sample.RSSKB
			}
		}
	}

	result.ElapsedMillis = time.Since(started).Milliseconds()
	result.RetainedTreeCount = len(retained)

	final := result.Samples[len(result.Samples)-1]
	result.FinalRSSKB = final.RSSKB
	result.DeltaRSSKB = result.FinalRSSKB - result.InitialRSSKB

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, "encode report:", err)
		os.Exit(1)
	}

	runtime.KeepAlive(retained)
}
