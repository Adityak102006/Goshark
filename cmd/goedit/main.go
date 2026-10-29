package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"goshark/internal/capturefile"
	"goshark/internal/edit"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

func run(arguments []string) (runErr error) {
	flags := flag.NewFlagSet("goedit", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	var keepExpression string
	var deduplicate bool
	var splitCount uint64
	var shiftExpression string
	var snaplen uint
	var startExpression string
	var endExpression string
	flags.StringVar(&keepExpression, "keep-ranges", "", "keep one-based packet ranges, such as 1-5,8")
	flags.BoolVar(&deduplicate, "dedupe", false, "remove repeated packet bytes and link types")
	flags.Uint64Var(&splitCount, "split-count", 0, "maximum packets per output part; zero disables splitting")
	flags.StringVar(&shiftExpression, "time-shift", "0s", "shift packet timestamps by a Go duration")
	flags.UintVar(&snaplen, "snaplen", 0, "truncate packet data to this many bytes; zero disables truncation")
	flags.StringVar(&startExpression, "start-time", "", "keep timestamps at or after this RFC3339 time")
	flags.StringVar(&endExpression, "end-time", "", "keep timestamps at or before this RFC3339 time")
	flags.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: goedit [options] INPUT OUTPUT")
		flags.PrintDefaults()
	}
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 2 {
		return errors.New("input and output capture paths are required")
	}
	ranges, err := edit.ParseRanges(keepExpression)
	if err != nil {
		return err
	}
	shift, err := time.ParseDuration(shiftExpression)
	if err != nil {
		return fmt.Errorf("invalid timestamp shift: %w", err)
	}
	if snaplen > 16<<20 {
		return errors.New("snaplen exceeds 16 MiB")
	}
	options := edit.Options{
		KeepRanges: ranges,
		Dedupe:     deduplicate,
		SplitCount: splitCount,
		TimeShift:  shift,
		Snaplen:    uint32(snaplen),
	}
	if startExpression != "" {
		start, err := edit.NewTime(startExpression)
		if err != nil {
			return err
		}
		options.StartTime = &start
	}
	if endExpression != "" {
		end, err := edit.NewTime(endExpression)
		if err != nil {
			return err
		}
		options.EndTime = &end
	}
	reader, err := capturefile.OpenFile(flags.Arg(0), capturefile.DefaultLimits())
	if err != nil {
		return err
	}
	defer func() {
		runErr = errors.Join(runErr, reader.Close())
	}()
	stats, err := edit.Run(reader, flags.Arg(1), options)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Read: %d, written: %d, duplicates: %d, outside selection: %d, parts: %d\n", stats.Read, stats.Written, stats.Duplicates, stats.Outside, stats.Parts)
	return nil
}
