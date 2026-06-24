package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// customKeyCharSet is a pre-built lookup for O(k) key validation instead of O(k·n).
var customKeyCharSet = func() map[rune]struct{} {
	m := make(map[rune]struct{}, len([]rune(customKeyCharset)))
	for _, r := range customKeyCharset {
		m[r] = struct{}{}
	}
	return m
}()

// validate reports whether s contains only characters from customKeyCharset.
// A trailing '~' (info-view suffix) is stripped before checking.
func validate(s string) bool {
	if len(s) == 0 {
		return true
	}
	if s[len(s)-1] == '~' {
		s = s[:len(s)-1]
	}
	for _, char := range s {
		if _, ok := customKeyCharSet[char]; !ok {
			return false
		}
	}
	return true
}

// initMaps will init and fill linkLen1, linkLen2 and linkLen3 with all valid free keys for each of them
func initLinkLens() {
	domainLinkLens = make(map[string]*LinkLens)

	for _, domain := range config.DomainNames {
		domainLinkLens[domain] = new(LinkLens)
		initLinkLensDomain(domain)
		// Start TimeoutManager for all key lengths. Defined in types.go
		go domainLinkLens[domain].LinkLen1.TimeoutManager()
		go domainLinkLens[domain].LinkLen2.TimeoutManager()
		go domainLinkLens[domain].LinkLen3.TimeoutManager()
		go domainLinkLens[domain].LinkCustom.TimeoutManager()
	}
}

func initLinkLensDomain(domain string) {
	domainLinkLens[domain].LinkLen1 = LinkLen{
		Mutex:   sync.RWMutex{},
		LinkMap: make(map[string]*Link),
		FreeMap: make(map[string]bool),
		Timeout: config.Clear1Duration,
		Domain:  domain,
		Type:    "len1",
	}

	domainLinkLens[domain].LinkLen2 = LinkLen{
		Mutex:   sync.RWMutex{},
		LinkMap: make(map[string]*Link),
		FreeMap: make(map[string]bool),
		Timeout: config.Clear2Duration,
		Domain:  domain,
		Type:    "len2",
	}

	domainLinkLens[domain].LinkLen3 = LinkLen{
		Mutex:   sync.RWMutex{},
		LinkMap: make(map[string]*Link),
		FreeMap: make(map[string]bool),
		Timeout: config.Clear3Duration,
		Domain:  domain,
		Type:    "len3",
	}

	domainLinkLens[domain].LinkCustom = LinkLen{
		Mutex:   sync.RWMutex{},
		LinkMap: make(map[string]*Link),
		Timeout: config.ClearCustomLinksDuration,
		Domain:  domain,
		Type:    "custom",
	}

	domainLinkLens[domain].LinkLen1.Mutex.Lock()
	defer domainLinkLens[domain].LinkLen1.Mutex.Unlock()
	domainLinkLens[domain].LinkLen2.Mutex.Lock()
	defer domainLinkLens[domain].LinkLen2.Mutex.Unlock()
	domainLinkLens[domain].LinkLen3.Mutex.Lock()
	defer domainLinkLens[domain].LinkLen3.Mutex.Unlock()

	for _, char1 := range charset {
		domainLinkLens[domain].LinkLen1.FreeMap[string(char1)] = true
		for _, char2 := range charset {
			domainLinkLens[domain].LinkLen2.FreeMap[string(char1)+string(char2)] = true
			for _, char3 := range charset {
				domainLinkLens[domain].LinkLen3.FreeMap[string(char1)+string(char2)+string(char3)] = true
			}
		}
	}
	if logger != nil {
		logger.Println("All maps initialized for", domain)
	}
}

// lookupLink returns a snapshot copy of the Link and its owning LinkLen for the
// given host+key. The copy is taken under the read lock, so callers may read any
// field of the returned *Link without holding a lock. Returns (nil, ll) if the key
// is not found (ll is still set so callers can pass it to recordAccess).
func lookupLink(host, key string) (*Link, *LinkLen) {
	dl, ok := domainLinkLens[host]
	if !ok {
		return nil, nil
	}
	var ll *LinkLen
	switch keylen := len(key); {
	case keylen == 1:
		ll = &dl.LinkLen1
	case keylen == 2:
		ll = &dl.LinkLen2
	case keylen == 3:
		ll = &dl.LinkLen3
	case keylen > 3 && keylen < maxKeyLen:
		ll = &dl.LinkCustom
	default:
		return nil, nil
	}
	ll.Mutex.RLock()
	lnkPtr := ll.LinkMap[key]
	var snap Link
	if lnkPtr != nil {
		snap = *lnkPtr // copy while holding the read lock
	}
	ll.Mutex.RUnlock()
	if lnkPtr == nil {
		return nil, ll
	}
	return &snap, ll
}

// recordAccess increments AccessCount and, for limited-use links (Times > 0),
// decrements Times under the write lock. If Times reaches zero the link is deleted
// from the map but a snapshot is returned so the caller can serve the final response.
// Returns nil if the link no longer exists (expired between lookupLink and now).
func recordAccess(ll *LinkLen, key string) *Link {
	ll.Mutex.Lock()
	defer ll.Mutex.Unlock()
	lnk, ok := ll.LinkMap[key]
	if !ok {
		return nil
	}
	lnk.AccessCount++
	if lnk.Times > 0 {
		lnk.Times--
		if lnk.Times <= 0 {
			snapshot := *lnk
			delete(ll.LinkMap, key)
			if ll.FreeMap != nil {
				ll.FreeMap[key] = true
			} else {
				ll.Links--
			}
			domain, typ := ll.Domain, ll.Type
			go deleteLinkFromDB(domain, typ, key)
			return &snapshot
		}
	}
	snapshot := *lnk
	return &snapshot
}

// findExistingURL returns the first active, unlimited-use URL link that points
// to targetURL for the given host, or nil if none exists.
// Only unlimited links (Times == -1) are matched to avoid silently consuming uses.
func findExistingURL(host, targetURL string) *Link {
	dl, ok := domainLinkLens[host]
	if !ok {
		return nil
	}
	search := func(ll *LinkLen) *Link {
		ll.Mutex.RLock()
		defer ll.Mutex.RUnlock()
		for _, lnk := range ll.LinkMap {
			if lnk.LinkType == "url" && lnk.Data == targetURL && lnk.Times == -1 {
				return lnk
			}
		}
		return nil
	}
	if lnk := search(&dl.LinkLen1); lnk != nil {
		return lnk
	}
	if lnk := search(&dl.LinkLen2); lnk != nil {
		return lnk
	}
	if lnk := search(&dl.LinkLen3); lnk != nil {
		return lnk
	}
	return search(&dl.LinkCustom)
}

var blocklist = make(map[string]struct{})

// loadBlocklist populates the blocklist from the config's BlockedDomains list
// and, if BlocklistFile is set, from a newline-delimited file (# comments OK).
func loadBlocklist() {
	for _, domain := range config.BlockedDomains {
		blocklist[strings.ToLower(strings.TrimSpace(domain))] = struct{}{}
	}
	if config.BlocklistFile == "" {
		return
	}
	data, err := os.ReadFile(config.BlocklistFile)
	if err != nil {
		if logger != nil {
			logger.Println("Failed to load blocklist file:", err)
		}
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		blocklist[line] = struct{}{}
	}
	if logger != nil {
		logger.Println("Loaded", len(blocklist), "entries into blocklist")
	}
}

// isBlocklisted returns true if the hostname of rawURL (or any parent domain)
// appears in the blocklist.
func isBlocklisted(rawURL string) bool {
	if len(blocklist) == 0 {
		return false
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	for host != "" {
		if _, blocked := blocklist[host]; blocked {
			return true
		}
		idx := strings.IndexByte(host, '.')
		if idx < 0 {
			break
		}
		host = host[idx+1:]
	}
	return false
}

func addHeaders(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("X-Content-Type-Options", "nosniff")
	w.Header().Add("Referrer-Policy", "no-referrer")
	if config.ReportTo != "" {
		w.Header().Add("Report-To", strings.ReplaceAll(config.ReportTo, "###DomainNames###", r.Host))
	}
	if !config.NoTLS && config.HSTS != "" {
		w.Header().Add("Strict-Transport-Security", config.HSTS)
	}
	if config.CSP != "" {
		w.Header().Add("Content-Security-Policy", strings.ReplaceAll(config.CSP, "###DomainNames###", r.Host))
	}
}

// validRequest returns true if the host string matches any of the valid hosts specified in the config and if the request is of a valid method (GET, POST)
func validRequest(r *http.Request) bool {
	var validHost, validType bool
	for _, d := range config.DomainNames {
		if r.Host == d {
			validHost = true
		}
	}

	if r.Method == "GET" || r.Method == "POST" {
		validType = true
	}

	return validHost && validType
}

func validURL(link string) bool {
	// simple sanity check to fail early, If len(link) is less than 11 it is definitely an invalid url link.
	if len(link) < 11 || !strings.HasPrefix(link, "http://") && !strings.HasPrefix(link, "https://") {
		return false
	}
	_, err := url.Parse(link)
	return err == nil
}

func lowRAM() bool {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.Sys > config.MaxRAM
}

func findFolderDefaultLocations(folder string) (path string) {
	if _, err := os.Stat(filepath.Join(".", folder)); !os.IsNotExist(err) {
		return filepath.Join(".", folder)
	}
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		// Fallback: use the default GOPATH convention ($HOME/go).
		if home, err := os.UserHomeDir(); err == nil {
			gopath = filepath.Join(home, "go")
		}
	}
	sep := ":"
	if runtime.GOOS == "windows" {
		sep = ";"
	}
	for _, dir := range strings.Split(gopath, sep) {
		candidate := filepath.Join(dir, "src", "github.com", "7i", "shorter", folder)
		if _, err := os.Stat(candidate); !os.IsNotExist(err) {
			return candidate
		}
	}
	return ""
}

// compress gzips data and returns it base64-encoded so it is safe for JSON storage.
func compress(data string) (string, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := io.Copy(zw, strings.NewReader(data)); err != nil {
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// decompress decodes a base64-encoded gzip payload produced by compress().
// Returns an error if the decompressed size exceeds maxDecompressedSize.
func decompress(data string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if _, err = io.Copy(&buf, io.LimitReader(zr, maxDecompressedSize+1)); err != nil {
		return "", err
	}
	if err = zr.Close(); err != nil {
		return "", err
	}
	if int64(buf.Len()) > maxDecompressedSize {
		return "", errors.New("decompressed size exceeds limit")
	}
	return buf.String(), nil
}

func returnDecompressed(lnk *Link, w http.ResponseWriter, r *http.Request) {
	if lnk == nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Error: nil lnk in returnDecompressed")
		return
	}
	raw, err := base64.StdEncoding.DecodeString(lnk.Data)
	if err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Error: base64 decode failed in returnDecompressed")
		return
	}
	dataReader, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Error: gzip open failed in returnDecompressed")
		return
	}
	if _, err = io.Copy(w, io.LimitReader(dataReader, maxDecompressedSize+1)); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Error: decompression failed in returnDecompressed")
		return
	}
	if err = dataReader.Close(); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Error: closing dataReader in returnDecompressed")
		return
	}
	logOK(r, http.StatusOK)
}

// logErrors will write the error to the log file, note that the arguments errStr and logStr should be escaped correctly with url.QueryEscape() if any user data is included.
func logErrors(w http.ResponseWriter, r *http.Request, errStr string, statusCode int, logStr string) {
	if logger != nil {
		logger.Println("Request:\nStatuscode:", statusCode, url.QueryEscape(logStr), url.QueryEscape(errStr), "\n", url.QueryEscape(r.Host+r.RequestURI), url.QueryEscape(r.RemoteAddr), url.QueryEscape(r.UserAgent()), url.QueryEscape(r.Referer()), url.QueryEscape(fmt.Sprintf("%v", r.PostForm)), url.QueryEscape(fmt.Sprintf("%v", r.Body)), url.QueryEscape(fmt.Sprintf("%v", r.Form)))
	}
	http.Error(w, errServerError, statusCode)
}

func logOK(r *http.Request, statusCode int) {
	if logger != nil {
		logger.Println("Request:\nStatuscode:", statusCode, url.QueryEscape(r.Host+r.RequestURI), url.QueryEscape(r.RemoteAddr), url.QueryEscape(r.UserAgent()), url.QueryEscape(r.Referer()), url.QueryEscape(fmt.Sprintf("%v", r.PostForm)), url.QueryEscape(fmt.Sprintf("%v", r.Body)), url.QueryEscape(fmt.Sprintf("%v", r.Form)))
	}
}

// listActiveLinks serves the admin link-list endpoint.
// Authentication uses HTTP Basic Auth; the password is sha256(password+Salt) == HashSHA256.
func listActiveLinks(w http.ResponseWriter, r *http.Request) {
	_, password, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="shorter admin"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	ba := sha256.Sum256([]byte(password + config.Salt))
	computed := hex.EncodeToString(ba[:])
	if subtle.ConstantTimeCompare([]byte(computed), []byte(config.HashSHA256)) == 1 {
		w.Header().Add("Content-Type", "text/plain")
		for _, domain := range config.DomainNames {
			fmt.Fprintf(w, "Domain: %s\nLinklen 1:\n%sLinklen 2:\n%sLinklen 3:\n%sCustom Links:\n%s",
				domain,
				getActiveList(&domainLinkLens[domain].LinkLen1),
				getActiveList(&domainLinkLens[domain].LinkLen2),
				getActiveList(&domainLinkLens[domain].LinkLen3),
				getActiveList(&domainLinkLens[domain].LinkCustom),
			)
		}
	} else {
		w.Header().Set("WWW-Authenticate", `Basic realm="shorter admin"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
}

func getActiveList(l *LinkLen) string {
	l.Mutex.RLock()
	defer l.Mutex.RUnlock()
	if l.NextClear == nil {
		return ""
	}
	var sb strings.Builder
	next := l.NextClear
	for next != nil {
		sb.WriteString("Domain: ")
		sb.WriteString(l.Domain)
		sb.WriteString(" Key: ")
		sb.WriteString(next.Key)
		sb.WriteString(" LinkType: ")
		sb.WriteString(next.LinkType)
		sb.WriteString(" IsCompressed: ")
		sb.WriteString(fmt.Sprintf("%v", next.IsCompressed))
		sb.WriteString(" Timeout: ")
		sb.WriteString(next.Timeout.String())
		sb.WriteString(" Data: ")
		if next.IsCompressed {
			sb.WriteString("<compressed>\n")
		} else {
			sb.WriteString(url.QueryEscape(next.Data))
			sb.WriteByte('\n')
		}
		next = next.NextClear
	}
	return sb.String()
}

func initTemplates() {
	// defaultIndex contains the hardcoded fallback for the index page
	defaultIndex := "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"><meta name=\"description\" content=\"Simple temporary URL shortener. Also supports temporary text blobs. 1-3 chars long or custom words.\"><meta name=\"Keywords\" content=\"temporary, temp, shortener, expiring, URL, link, redirect, generator\"><title>Temporary URL shortener</title><link rel=\"icon\" type=\"image/png\" href=\"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAABSUlEQVQ4jZ2Tu0oDURCG90myKwERC8FKfAAfwdZCsU0bmwhWglY2Ad2zRhS0sUshsUiRRjQgMQYEG20khezZZO+5bD6LQGJINpoUfzPDfDNz5vxKQpj7qrBCTUhmkSqsUNWtjKIJ2Zq1eADRZajMWrR1Z3Py7LN2baEJiaIJSbbiYwbRVB0+emhC0gwjAPSqPwTo1QCv3RtTq9sDoBFGrFz2O+4UbLIVn/WbXxPEqVxvA3Bc9gaxzXyTVNEZXWGSdu9tAL79iOWLYbzw2QJgu+DEA5KG5F12ADh48EZy/wKkSy4AX06XxXM5G2ApJ6m7XQD2Su4Y/E/A0ZMHwEejS9IYn24qYPXKwm7175wqOhMfdyrAeA0AeDM7LMRcJxaQNCSnLz65WsBmvhn7N9Ill1wtYOO20QfM48SBmYQVKomzOe2sy1DVzcwP7InxY4zEPaQAAAAASUVORK5CYII=\"><link rel=\"stylesheet\" type=\"text/css\" href=\"shorter.css\" integrity=\"sha256-Q1KumqswQnGssQv5JsnHhB4U20pPESF8eVZw9sPxm7Y=\" crossorigin=\"anonymous\"></head><body><div class=\"content\"><div><div class=\"header\"><img src=\"logo.png\"><h1>Temp Url shortener</h1></div><form id=\"shortener\" method=\"POST\" enctype=\"multipart/form-data\"><div class=\"radio-box\"><input type=\"radio\" name=\"len\" id=\"hideCustomKey1\" value=\"1\" checked><label for=\"len\">Length 1: valid for 24h</label><input type=\"radio\" name=\"len\" id=\"hideCustomKey2\" value=\"2\"><label for=\"len\">Length 2: valid for 7d</label><input type=\"radio\" name=\"len\" id=\"hideCustomKey3\" value=\"3\"><label for=\"len\">Length 3: valid for 60d</label><input type=\"radio\" name=\"len\" id=\"showCustomKey\" value=\"custom\"><label for=\"len\">Custom key (4-64 chars): valid for 30d</label><div id=\"customDiv\"><span>Custom key:</span><input type=\"text\" name=\"custom\" class=\"inputbox\" placeholder=\"Your Custom Key Here\"></div></div><div class=\"radio-box\"><input type=\"radio\" name=\"requestType\" id=\"showURL\" value=\"url\" checked><label for=\"requestType\">Create temporary URL</label><input type=\"radio\" name=\"requestType\" id=\"showText\" value=\"text\"><label for=\"requestType\">Temporary text dump</label><div id=\"urlDiv\"><span>Submit URL to shorten:</span><input type=\"text\" name=\"url\" class=\"inputbox\" placeholder=\"Your URL Here\"></div><div id=\"textDiv\"><span>Submit text to temporarly save:</span><textarea form=\"shortener\" rows=\"7\" cols=\"80\" name=\"text\"></textarea></div></div><input type=\"submit\"></form></div><div class=\"info\"><span>Pre Alpha test site, links will be cleared during development without notice.</span></div><div class=\"tos\"><input id=\"ToS\" type=\"radio\" name=\"ToS\" /><label for=\"ToS\">Terms of Service</label><div id=\"ToSDiv\">The 7i service may not be used for any unlawful activities including but not limited to <br>scamming, fraud, transmission of viruses, trojan horses, or other malware.<br>7i reserves the right to modify anything in the 7i service without any prior notice including<br>but not limited to shutting down the service or deleting any content generated by any party.<br>By using the 7i service you acknowledge that any data sent to the 7i service will be provided <br>under the Zero-Clause BSD license (https://opensource.org/licenses/0BSD) and that you have <br>the right to upload the data. <br><br>THE 7I SERVICE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR <br>IMPLIED. USE OF THE 7I SERVICES IS SOLELY AT YOUR OWN RISK. IN NO EVENT SHALL THE <br>AUTHORS, 7I OR THE PROVIDER OF THE 7I SERVICE BE LIABLE FOR ANY CLAIM, DAMAGES <br>OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, <br>ARISING FROM, OUT OF OR IN CONNECTION WITH THE SERVICE OR SOFTWARE OR THE USE <br>OR OTHER DEALINGS IN THE SERVICE OR SOFTWARE. 7I TRIES TO LIMIT ANY UNLAWFUL <br>ACTIVITIES BY ITS USERS BUT DOES NOT WARRANT THAT THE 7I SERVICE IS SECURE, FREE <br>OF VIRUSES OR OTHER HARMFUL COMPONENTS</div></div></div></body></html>"
	// defaultShowLink contains the hardcoded fallback for the showLink page
	defaultShowLink := "<!DOCTYPE html><html lang=\"en\"><head><link rel=\"stylesheet\" type=\"text/css\" href=\"shorter.css\"></head><body><div class=\"content\"><div class=\"tos\">Temporary link:<br><H1><a href=\"{{.Data}}\">{{.Data}}</a></H1><br>This link will be removed {{.Timeout}}</div><div class=\"info\">Please only navigate to the link if you trust the person that generated the link.</div><div class=\"tos\">To create your own temporary links please visit <a href=\"{{.Domain}}\">{{.Domain}}</a></div></div></body></html>"

	// templateMap should be used as read only after initTemplates() has returned
	templateMap = make(map[string]*template.Template)
	// Create index page
	loadTemplate("index", defaultIndex)
	// Create page for showing links
	loadTemplate("showLink", defaultShowLink)
}

func loadTemplate(templateName, defaultTmplStr string) {
	defaultTmpl := template.Must(template.New(templateName + ".tmpl").Parse(defaultTmplStr))

	for _, domain := range config.DomainNames {
		tmpl, err := template.ParseFiles(filepath.Join(config.BaseDir, domain, templateName+".tmpl"))
		if err != nil {
			if logger != nil {
				logger.Println("Missing /" + domain + "/" + templateName + ".tmpl in Template dir, fallback to default " + templateName + ".tmpl with key: " + domain + "#" + templateName)
			}
			templateMap[domain+"#"+templateName] = defaultTmpl
		} else {
			if logger != nil {
				logger.Println("Template key value: ", domain+"#"+templateName)
			}
			templateMap[domain+"#"+templateName] = tmpl
		}
	}
}
