package kiro

import "github.com/xiaokui-dev/cliproxyapi-kiro-plugin/internal/hostapi"

// Test seams: indirection over the host callbacks so the auth / executor / usage
// handlers can be unit-tested without a live host. Tests replace these package
// variables and restore them via t.Cleanup.
var (
	kiroHTTPDo          = hostapi.HTTPDo
	kiroHTTPDoStream    = hostapi.HTTPDoStream
	kiroHTTPStreamRead  = hostapi.HTTPStreamRead
	kiroHTTPStreamClose = hostapi.HTTPStreamClose
	kiroStreamEmit      = hostapi.StreamEmit
	kiroStreamClose     = hostapi.StreamClose
	hostAuthListFn      = hostapi.AuthList
	hostAuthGetFn       = hostapi.AuthGet
)
