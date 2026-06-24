package main

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"

	bbolt "go.etcd.io/bbolt"
)

var linkLenTypes = []string{"len1", "len2", "len3", "custom"}

// setupDB opens (or creates) the bbolt database, prunes expired entries, and
// restores surviving links into memory. Falls back to legacy gob files if the
// database cannot be opened.
func setupDB() {
	if logger != nil {
		logger.Println("Opening bbolt database")
	}

	dbPath := filepath.Join(config.BaseDir, "shorter.db")
	var err error
	boltDB, err = bbolt.Open(dbPath, 0600, &bbolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		if logger != nil {
			logger.Println("Failed to open bbolt DB, falling back to gob backup:", err)
		}
		for _, domain := range config.DomainNames {
			restoreGob(&domainLinkLens[domain].LinkLen1, "len1", domain)
			restoreGob(&domainLinkLens[domain].LinkLen2, "len2", domain)
			restoreGob(&domainLinkLens[domain].LinkLen3, "len3", domain)
			restoreGob(&domainLinkLens[domain].LinkCustom, "custom", domain)
		}
		return
	}

	// Ensure all domain/type buckets exist.
	if err = boltDB.Update(func(tx *bbolt.Tx) error {
		for _, domain := range config.DomainNames {
			b, err := tx.CreateBucketIfNotExists([]byte(domain))
			if err != nil {
				return err
			}
			for _, t := range linkLenTypes {
				if _, err = b.CreateBucketIfNotExists([]byte(t)); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil && logger != nil {
		logger.Println("Failed to create bbolt buckets:", err)
	}

	// Restore links, pruning any that have already expired.
	now := time.Now()
	boltDB.Update(func(tx *bbolt.Tx) error {
		for _, domain := range config.DomainNames {
			b := tx.Bucket([]byte(domain))
			if b == nil {
				return nil
			}
			for _, typ := range linkLenTypes {
				tb := b.Bucket([]byte(typ))
				if tb == nil {
					continue
				}
				ll := llForType(domain, typ)

				var active []Link
				var toDelete [][]byte

				tb.ForEach(func(k, v []byte) error {
					var lnk Link
					if json.Unmarshal(v, &lnk) != nil {
						toDelete = append(toDelete, append([]byte(nil), k...))
						return nil
					}
					if !lnk.Timeout.After(now) {
						toDelete = append(toDelete, append([]byte(nil), k...))
						return nil
					}
					active = append(active, lnk)
					return nil
				})
				for _, k := range toDelete {
					tb.Delete(k)
				}

				// Sort ascending by Timeout so NextClear linked list stays ordered.
				sort.Slice(active, func(i, j int) bool {
					return active[i].Timeout.Before(active[j].Timeout)
				})
				for i := range active {
					restoreLinkToMemory(ll, &active[i])
				}
			}
		}
		return nil
	})

	if logger != nil {
		logger.Println("bbolt restore complete")
	}
}

func llForType(domain, typ string) *LinkLen {
	switch typ {
	case "len1":
		return &domainLinkLens[domain].LinkLen1
	case "len2":
		return &domainLinkLens[domain].LinkLen2
	case "len3":
		return &domainLinkLens[domain].LinkLen3
	default:
		return &domainLinkLens[domain].LinkCustom
	}
}

// restoreLinkToMemory inserts lnk directly into ll's in-memory structures
// without triggering a DB write. Links must be inserted in ascending Timeout order.
func restoreLinkToMemory(l *LinkLen, lnk *Link) {
	lnk.NextClear = nil
	l.LinkMap[lnk.Key] = lnk
	if l.FreeMap != nil {
		delete(l.FreeMap, lnk.Key)
	} else {
		l.Links++
	}
	if l.NextClear == nil {
		l.NextClear = lnk
		l.EndClear = lnk
	} else {
		l.EndClear.NextClear = lnk
		l.EndClear = lnk
	}
}

// saveLinkToDB persists lnk to bbolt. Called after a successful Add(), outside
// the LinkLen mutex so it doesn't block readers.
func saveLinkToDB(domain, typ string, lnk *Link) {
	if boltDB == nil {
		return
	}
	data, err := json.Marshal(lnk)
	if err != nil {
		if logger != nil {
			logger.Println("saveLinkToDB marshal error:", err)
		}
		return
	}
	if err = boltDB.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(domain))
		if b == nil {
			return nil
		}
		return b.Bucket([]byte(typ)).Put([]byte(lnk.Key), data)
	}); err != nil && logger != nil {
		logger.Println("saveLinkToDB write error:", err)
	}
}

// deleteLinkFromDB removes a key from bbolt. Called by TimeoutManager when a
// link expires and by recordAccess when Times reaches zero.
func deleteLinkFromDB(domain, typ, key string) {
	if boltDB == nil {
		return
	}
	if err := boltDB.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(domain))
		if b == nil {
			return nil
		}
		return b.Bucket([]byte(typ)).Delete([]byte(key))
	}); err != nil && logger != nil {
		logger.Println("deleteLinkFromDB error:", err)
	}
}

// restoreGob is the legacy fallback: restores links from a gob backup file.
func restoreGob(l *LinkLen, typ, domain string) {
	fileName := "backupdb-" + domain + "-" + typ + ".gob"
	d, err := os.ReadFile(filepath.Join(config.BaseDir, domain, fileName))
	if err != nil {
		if logger != nil {
			logger.Println(err, "restoreGob - skipping "+fileName)
		}
		return
	}
	var links []Link
	if err = gob.NewDecoder(bytes.NewBuffer(d)).Decode(&links); err != nil {
		if logger != nil {
			logger.Println(err, "restoreGob - decode error "+fileName)
		}
		return
	}
	now := time.Now()
	sort.Slice(links, func(i, j int) bool {
		return links[i].Timeout.Before(links[j].Timeout)
	})
	for i := range links {
		if links[i].Key != "" && links[i].Timeout.After(now) {
			restoreLinkToMemory(l, &links[i])
		}
	}
}
