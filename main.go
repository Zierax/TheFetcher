package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// WebURL struct to hold date and URL
type WebURL struct {
	Date string
	URL  string
}

// FetchFunc defines the signature for functions that fetch URLs
type FetchFunc func(string, bool) ([]WebURL, error)

func main() {
	// Command-line flags
	var (
		domains         []string
		dates           bool
		noSubs          bool
		getVersionsFlag bool
		wordlist        string // New flag for wordlist file
		findParams      bool   // New flag for finding parameters
		help            bool
	)

	flag.BoolVar(&dates, "dates", false, "show date of fetch in the first column")
	flag.BoolVar(&noSubs, "no-subs", false, "don't include subdomains of the target domain")
	flag.BoolVar(&getVersionsFlag, "get-versions", false, "list URLs for crawled versions of input URL(s)")
	flag.BoolVar(&findParams, "find-params", false, "find parameters from URLs in wordlist")
	flag.BoolVar(&help, "help", false, "show help menu")
	flag.StringVar(&wordlist, "wordlist", "", "specify a wordlist file for fuzzing")
	flag.Parse()

	if help || (flag.NArg() == 0 && flag.NFlag() == 0) {
		flag.Usage()
		return
	}

	// Read domains from arguments or stdin
	if flag.NArg() > 0 {
		domains = flag.Args()
	} else if wordlist != "" { // Read domains from wordlist if provided
		var err error
		if findParams {
			domains, err = findParametersFromWordlist(wordlist)
		} else {
			domains, err = readWordlist(wordlist)
		}
		if err != nil {
			log.Fatalf("failed to read wordlist file: %v", err)
		}
	} else {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			domains = append(domains, sc.Text())
		}
		if err := sc.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to read input: %s\n", err)
			os.Exit(1)
		}
	}

	// Handle get-versions mode
	if getVersionsFlag {
		for _, u := range domains {
			versions, err := getVersions(u)
			if err != nil {
				log.Printf("Error getting versions for %s: %v", u, err)
				continue
			}
			fmt.Println(strings.Join(versions, "\n"))
		}
		return
	}

	// Define fetch functions
	fetchFuncs := []FetchFunc{
		getWaybackURLs,
		getCommonCrawlURLs,
		getVirusTotalURLs,
	}

	// Iterate over domains
	for _, domain := range domains {
		var wg sync.WaitGroup
		wurls := make(chan WebURL)

		// Concurrently fetch URLs using different fetch functions
		for _, fn := range fetchFuncs {
			wg.Add(1)
			fetch := fn
			go func() {
				defer wg.Done()
				resp, err := fetch(domain, noSubs)
				if err != nil {
					log.Printf("Error fetching data for %s: %v", domain, err)
					return
				}
				for _, r := range resp {
					if noSubs && isSubdomain(r.URL, domain) {
						continue
					}
					wurls <- r
				}
			}()
		}

		// Close channel when all fetch operations are done
		go func() {
			wg.Wait()
			close(wurls)
		}()

		// Track seen URLs to avoid duplicates
		seen := make(map[string]bool)

		// Print fetched URLs
		for w := range wurls {
			if _, ok := seen[w.URL]; ok {
				continue
			}
			seen[w.URL] = true
			if dates {
				d, err := time.Parse("20060102150405", w.Date)
				if err != nil {
					fmt.Fprintf(os.Stderr, "failed to parse date [%s] for URL [%s]\n", w.Date, w.URL)
					continue
				}
				fmt.Printf("%s %s\n", d.Format(time.RFC3339), w.URL)
			} else {
				fmt.Println(w.URL)
			}
		}
	}
}

// Fetch URLs from Wayback Machine
func getWaybackURLs(domain string, noSubs bool) ([]WebURL, error) {
	subsWildcard := "*."
	if noSubs {
		subsWildcard = ""
	}
	res, err := http.Get(fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=%s%s/*&output=json&collapse=urlkey", subsWildcard, domain))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	raw, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var wrapper [][]string
	err = json.Unmarshal(raw, &wrapper)
	if err != nil {
		return nil, err
	}

	out := make([]WebURL, 0, len(wrapper))
	skip := true
	for _, urls := range wrapper {
		if skip {
			skip = false
			continue
		}
		out = append(out, WebURL{Date: urls[1], URL: urls[2]})
	}
	return out, nil
}

// Fetch URLs from Common Crawl
func getCommonCrawlURLs(domain string, noSubs bool) ([]WebURL, error) {
	subsWildcard := "*."
	if noSubs {
		subsWildcard = ""
	}
	res, err := http.Get(fmt.Sprintf("http://index.commoncrawl.org/CC-MAIN-2018-22-index?url=%s%s/*&output=json", subsWildcard, domain))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	sc := bufio.NewScanner(res.Body)
	out := make([]WebURL, 0)
	for sc.Scan() {
		wrapper := struct {
			URL       string `json:"url"`
			Timestamp string `json:"timestamp"`
		}{}
		err = json.Unmarshal([]byte(sc.Text()), &wrapper)
		if err != nil {
			continue
		}
		out = append(out, WebURL{Date: wrapper.Timestamp, URL: wrapper.URL})
	}
	return out, nil
}

// Fetch URLs from VirusTotal
func getVirusTotalURLs(domain string, noSubs bool) ([]WebURL, error) {
	out := make([]WebURL, 0)
	apiKey := os.Getenv("VT_API_KEY")
	if apiKey == "" {
		return out, nil
	}
	fetchURL := fmt.Sprintf("https://www.virustotal.com/vtapi/v2/domain/report?apikey=%s&domain=%s", apiKey, domain)
	resp, err := http.Get(fetchURL)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()

	wrapper := struct {
		URLs []struct {
			URL string `json:"url"`
		} `json:"detected_urls"`
	}{}
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&wrapper)
	if err != nil {
		return out, err
	}
	for _, u := range wrapper.URLs {
		out = append(out, WebURL{URL: u.URL})
	}
	return out, nil
}

// Check if a URL is a subdomain of a given domain
func isSubdomain(rawURL, domain string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return strings.ToLower(u.Hostname()) != strings.ToLower(domain)
}

// Fetch archived versions of a given URL
func getVersions(u string) ([]string, error) {
	out := make([]string, 0)
	resp, err := http.Get(fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=%s&output=json", u))
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()

	r := [][]string{}
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&r)
	if err != nil {
		return out, err
	}

	first := true
	seen := make(map[string]bool)
	for _, s := range r {
		if first {
			first = false
			continue
		}
		if seen[s[5]] {
			continue
		}
		seen[s[5]] = true
		out = append(out, fmt.Sprintf("https://web.archive.org/web/%sif_/%s", s[1], s[2]))
	}
	return out, nil
}

// Read domains from wordlist file
func readWordlist(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var domains []string
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		domains = append(domains, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return domains, nil
}

// Find parameters from URLs in wordlist
func findParametersFromWordlist(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var parameters []string
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		u, err := url.Parse(sc.Text())
		if err != nil {
			continue
		}
		queryParams := u.Query()
		for key := range queryParams {
			parameters = append(parameters, key)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return parameters, nil
}
