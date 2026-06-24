package main

import (
	"net"
	"sync"
	"time"
)

const (
	rateLimitMax    = 30           // max POST requests per IP per window
	rateLimitWindow = time.Minute  // sliding window duration
)

type ipRate struct {
	count     int
	windowEnd time.Time
}

var (
	rateMu      sync.Mutex
	rateClients = make(map[string]*ipRate)
)

func init() {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		for range ticker.C {
			now := time.Now()
			rateMu.Lock()
			for ip, r := range rateClients {
				if now.After(r.windowEnd) {
					delete(rateClients, ip)
				}
			}
			rateMu.Unlock()
		}
	}()
}

// rateLimitAllow returns true if the request is within the rate limit for the given remoteAddr.
func rateLimitAllow(remoteAddr string) bool {
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		ip = remoteAddr
	}
	now := time.Now()
	rateMu.Lock()
	defer rateMu.Unlock()
	cl, ok := rateClients[ip]
	if !ok || now.After(cl.windowEnd) {
		rateClients[ip] = &ipRate{count: 1, windowEnd: now.Add(rateLimitWindow)}
		return true
	}
	cl.count++
	return cl.count <= rateLimitMax
}
