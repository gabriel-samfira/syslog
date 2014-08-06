// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !windows,!plan9

package syslog

import (
	"testing"
)

var transports = []string{"unix", "unixgram", "udp", "tcp"}

func TestNew(t *testing.T) {
	if LOG_LOCAL7 != 23<<3 {
		t.Fatalf("LOG_LOCAL7 has wrong value")
	}
	if testing.Short() {
		// Depends on syslog daemon running, and sometimes it's not.
		t.Skip("skipping syslog test during -short")
	}

	s, err := New(LOG_INFO|LOG_USER, "the_tag")
	if err != nil {
		t.Fatalf("New() failed: %s", err)
	}
	// Don't send any messages.
	s.Close()
}

func TestNewLogger(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping syslog test during -short")
	}
	f, err := NewLogger(LOG_USER|LOG_INFO, 0)
	if f == nil {
		t.Error(err)
	}
}

func TestLocalDial(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping syslog test during -short")
	}
	f, err := Dial("", "", (LOG_LOCAL7|LOG_DEBUG)+1, "syslog_test", nil)
	if f != nil {
		t.Fatalf("Should have trapped bad priority")
	}
	f, err = Dial("", "", -1, "syslog_test", nil)
	if f != nil {
		t.Fatalf("Should have trapped bad priority")
	}
	l, err := Dial("", "", LOG_USER|LOG_ERR, "syslog_test", nil)
	if err != nil {
		t.Fatalf("Dial() failed: %s", err)
	}
	l.Close()
}
