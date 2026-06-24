package main

import (
	"html/template"
	"log"

	bbolt "go.etcd.io/bbolt"
)

const (
	// charset consists of alphanumeric characters with some characters removed due to them being to similar in some fonts.
	charset = "abcdefghijkmnopqrstuvwxyz23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
	// customKeyCharset consists of characters that are valid for custom keys.
	customKeyCharset = "abcdefghijklmnopqrstuvwxyzåäö0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZÅÄÖ-_"
	// dateFormat specifies the format in which date and time is represented.
	dateFormat = "Mon 2006-01-02 15:04 MST"
	// errServerError contains the generic error message users will see when something goes wrong
	errServerError      = "Internal Server Error"
	errInvalidKey       = "Invalid key"
	errInvalidKeyUsed   = "Invalid key, key is already in use"
	errInvalidCustomKey = "Invalid Custom Key was provided, valid characters are:\n" + customKeyCharset
	errNotImplemented   = "Not Implemented"
	errLowRAM           = "No Space available, new space will be available as old links become invalid"
	// Do not try to gzip data that is less than minSizeToGzip bytes
	minSizeToGzip = 128
	// maxKeyLen is the maximum length of a custom key
	maxKeyLen = 64
	// maxDecompressedSize caps how many bytes returnDecompressed / decompress will inflate.
	maxDecompressedSize = 20 << 20 // 20 MiB
)

var (
	// logSep is a 128-bit random value combined with config.LogSep to make log entries hard to forge.
	logSep string
	// config holds the parsed server configuration.
	config Config
	// domainLinkLens contains per-domain link buckets for all key lengths.
	domainLinkLens map[string]*LinkLens
	// logger writes structured entries to the configured log file; nil means logging is disabled.
	logger *log.Logger

	// ImageMap maps "domain-logo" / "domain-favicon" keys to their PNG bytes.
	ImageMap map[string][]byte

	templateMap map[string]*template.Template

	// boltDB is the persistent store; nil means DB unavailable (gob fallback used).
	boltDB *bbolt.DB
)
