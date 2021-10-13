package gau

import (
	"crypto/tls"
	"fmt"
	"github.com/remeh/sizedwaitgroup"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"gourls/gau/output"
	"gourls/gau/providers"
)

func run(config *providers.Config, domains []string) []string{
	var providerList []providers.Provider
	var resultslist []string
	for _, toUse := range config.Providers {
		switch toUse {
		case "wayback":
			wayback := providers.NewWaybackProvider(config)
			providerList = append(providerList, wayback)
		case "otx":
			otx := providers.NewOTXProvider(config)
			providerList = append(providerList, otx)
		case "commoncrawl":
			common, err := providers.NewCommonProvider(config)
			if err == nil {
				providerList = append(providerList, common)
			}
		default:
			fmt.Fprintf(os.Stderr, "Error: %s is not a valid provider.\n", toUse)
		}
	}

	results := make(chan string)
	var out io.Writer
	// Handle results in background
	if config.Output == "" {
		out = os.Stdout
	} else {
		ofp, err := os.OpenFile(config.Output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("Could not open output file: %v\n", err)
		}
		defer ofp.Close()
		out = ofp
	}

	writewg := &sync.WaitGroup{}
	writewg.Add(1)
	if config.JSON {
		go func() {
			output.WriteURLsJSON(results, out, config.Blacklist)
			writewg.Done()
		}()
	} else {
		go func() {
		
			resultslist = output.WriteURLs(results, out, config.Blacklist)
			writewg.Done()
		}()
	}
	if config.Threads > 50 {
		config.Threads = 50
	}

	dwg := sizedwaitgroup.New(int(config.Threads))
	wg := &sync.WaitGroup{}

	for _, domain := range domains {
		dwg.Add()
		// Run all providers in parallel
		wg.Add(len(providerList))

		for _, provider := range providerList {
			go func(provider providers.Provider) {
				defer wg.Done()
				if err := provider.Fetch(domain, results); err != nil {
					if config.Verbose {
						_, _ = fmt.Fprintln(os.Stderr, err)
					}
				}
			}(provider)
		}
		wg.Wait()
		dwg.Done()
	}

	dwg.Wait()

	close(results)

	// Wait for writer to finish
	writewg.Wait()
	return resultslist
}

func Gau(domain string) []string{
	var domains []string
	verbose := false
	includeSubs := true
	useProviders := "otx"//flag.String("providers", "wayback,otx,commoncrawl", "providers to fetch urls for")
	version := false
	proxy := ""//flag.String("p", "", "HTTP proxy to use")
	//threads := flag.Uint("t", 1, "number of threads to use")
	output := ""//flag.String("o", "", "filename to write results to")
	jsonOut := false//flag.Bool("json", false, "write output as json")
	blacklist := ""//flag.String("b", "", "extensions to skip, ex: ttf,woff,svg,png,jpg")


	if version {
		fmt.Printf("gau version: %s\n", providers.Version)
		os.Exit(0)
	}

	
	domains = append(domains, domain)

	tr := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 5 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
	}

	if proxy != "" {
		if p, err := url.Parse(proxy); err == nil {
			tr.Proxy = http.ProxyURL(p)
		}
	}

	extensions := strings.Split(blacklist, ",")
	extMap := make(map[string]struct{})
	for _, ext := range extensions {
		extMap[strings.ToLower(ext)] = struct{}{}
	}
	config := providers.Config{
		Threads:           20,
		Verbose:           verbose,
		MaxRetries:        5,
		IncludeSubdomains: includeSubs,
		Output:            output,
		JSON:              jsonOut,
		Blacklist:         extMap,
		Client: &http.Client{
			Timeout:   time.Second * 15,
			Transport: tr,
		},
		Providers: strings.Split(useProviders, ","),
	}
	resultslist := run(&config, domains)
	return resultslist
}
