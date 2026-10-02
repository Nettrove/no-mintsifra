package proxy

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// Stage names the step of a connection that went wrong.
type Stage string

const (
	StageConnect    Stage = "connect"
	StageDial       Stage = "upstream-dial"
	StageVerify     Stage = "upstream-verify"
	StageClient     Stage = "client-handshake"
	StageALPN       Stage = "alpn"
	StageRecovered  Stage = "panic"
	StagePin        Stage = "pin"
	maxEventMessage       = 300
)

// Event is one failed or suspicious connection. It never holds traffic,
// only where and why the connection stopped or drew attention.
type Event struct {
	Time  time.Time
	Host  string
	Stage Stage
	Err   string
}

func (e Event) String() string {
	return fmt.Sprintf("%s\t%s\t%s\t%s", e.Time.Format(time.RFC3339), e.Stage, e.Host, e.Err)
}

// Log keeps the latest events in memory and appends them to a file that is
// rotated by size, so it stays bounded on disk too.
type Log struct {
	Path    string
	MaxSize int64

	mu      sync.Mutex
	ring    []Event
	next    int
	pending []Event
}

// NewLog keeps up to size events in memory.
func NewLog(path string, size int, maxFile int64) *Log {
	return &Log{Path: path, MaxSize: maxFile, ring: make([]Event, 0, size)}
}

func (l *Log) Add(e Event) {
	if l == nil {
		return
	}
	e.Err = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		return r
	}, e.Err)
	if len(e.Err) > maxEventMessage {
		e.Err = e.Err[:maxEventMessage]
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.ring) < cap(l.ring) {
		l.ring = append(l.ring, e)
	} else {
		l.ring[l.next] = e
		l.next = (l.next + 1) % len(l.ring)
	}
	if len(l.pending) < cap(l.ring) {
		l.pending = append(l.pending, e)
	}
}

// Recent returns the events in memory, oldest first.
func (l *Log) Recent() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append(append([]Event(nil), l.ring[l.next:]...), l.ring[:l.next]...)
}

// Flush appends the events not yet written, moving a full file to Path.1.
func (l *Log) Flush() error {
	l.mu.Lock()
	batch := l.pending
	l.pending = nil
	l.mu.Unlock()
	if len(batch) == 0 || l.Path == "" {
		return nil
	}
	if fi, err := os.Stat(l.Path); err == nil && fi.Size() > l.MaxSize {
		_ = os.Rename(l.Path, l.Path+".1")
	}
	f, err := os.OpenFile(l.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	var b strings.Builder
	for _, e := range batch {
		b.WriteString(e.String())
		b.WriteByte('\n')
	}
	_, err = f.WriteString(b.String())
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// Run flushes every interval until ctx ends.
func (l *Log) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = l.Flush()
			return
		case <-t.C:
			_ = l.Flush()
		}
	}
}
