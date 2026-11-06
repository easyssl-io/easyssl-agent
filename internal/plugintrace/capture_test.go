package plugintrace

import (
	"strings"
	"testing"
)

// A Plugin that writes without newlines is held to the bound like one that
// writes lines: past it the line is counted as dropped, not kept in memory.
func TestALineWithoutANewlineIsBounded(t *testing.T) {
	c := &Capture{Max: 1024}
	w := c.Writer(StreamStdout)
	for i := 0; i < 100; i++ {
		_, _ = w.Write([]byte(strings.Repeat("x", 512)))
	}
	if len(w.partial) > c.Max {
		t.Fatalf("the writer holds %d bytes of one line, more than the bound %d", len(w.partial), c.Max)
	}
	_, _ = w.Write([]byte("\nafter\n"))
	w.Flush()
	if got := c.Produced(StreamStdout); got != 100*512+1+len("after\n") {
		t.Fatalf("produced %d bytes, want every byte counted", got)
	}
	if got := c.Text(StreamStdout); got != "" {
		t.Fatalf("kept %q, want nothing once the stream was cut", got)
	}

	ok := &Capture{Max: 1024}
	ow := ok.Writer(StreamStderr)
	_, _ = ow.Write([]byte("par"))
	_, _ = ow.Write([]byte("tial\nlast"))
	ow.Flush()
	if got := ok.Text(StreamStderr); got != "partial\nlast\n" {
		t.Fatalf("kept %q, want both lines", got)
	}
}
