package hakrawle

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/gocolly/colly"
)

var headers map[string]string
var resultlists []string

func Hakrawle(url string) []string{
	threads := 8
	depth := 3
	insecure := false
	rawHeaders := "" //flag.String(("h"), "", "Custom headers separated by semi-colon. E.g. -h \"Cookie: foo=bar\" ")


	// Convert the headers input to a usable map (or die trying)
	err := parseHeaders(rawHeaders)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error parsing headers:", err)
		os.Exit(1)
	}
	// get each line of stdin, push it to the work channel

	crawl(url, threads, depth, insecure)
	//fmt.Printf("%v", resultlists)
	return resultlists
}

func crawl(url string, threads int, depth int, insecure bool) {
	// Instantiate default collector
	c := colly.NewCollector(
		// set MaxDepth to the specified depth, and specify Async for threading
		colly.MaxDepth(depth),
		colly.Async(true),
	)

	// Set parallelism
	c.Limit(&colly.LimitRule{DomainGlob: "*", Parallelism: threads})

	// Print every href found, and visit it
	c.OnHTML("a[href]", func(e *colly.HTMLElement) {
		link := e.Attr("href")
		// Print link
		absoluteURL := e.Request.AbsoluteURL(link)

		if absoluteURL != "" && strings.Contains(absoluteURL, url){
			resultlists = append(resultlists,e.Request.AbsoluteURL(link))
			//fmt.Printf("%s\n", e.Request.AbsoluteURL(link))
			// Visit link found on page on a new thread
			e.Request.Visit(link)
		}
	})

	// find and print all the JavaScript files
	c.OnHTML("script[src]", func(e *colly.HTMLElement) {
		link := e.Attr("src")
		absoluteURL := e.Request.AbsoluteURL(link)
		if absoluteURL != "" && strings.Contains(absoluteURL, url){
			resultlists = append(resultlists,e.Request.AbsoluteURL(link))
			//fmt.Printf("%s\n", e.Request.AbsoluteURL(link))
		}
	})

	// find and print all the JavaScript files
	c.OnHTML("form[action]", func(e *colly.HTMLElement) {
		link := e.Attr("action")
		absoluteURL := e.Request.AbsoluteURL(link)
		if absoluteURL != "" && strings.Contains(absoluteURL, url){
			resultlists = append(resultlists,e.Request.AbsoluteURL(link))
			//fmt.Printf("%s\n", e.Request.AbsoluteURL(link))
		}
	})

	// add the custom headers
	if headers != nil {
		c.OnRequest(func(r *colly.Request) {
			for header, value := range headers {
				r.Headers.Set(header, value)
			}
		})
	}

	// Skip TLS verification if -insecure flag is present
	c.WithTransport(&http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
	})

	// Start scraping
	c.Visit(url)
	// Wait until threads are finished
	c.Wait()
}

// parseHeaders does validation of headers input and saves it to a formatted map.
func parseHeaders(rawHeaders string) error {
	if rawHeaders != "" {
		if !strings.Contains(rawHeaders, ":") {
			return errors.New("headers flag not formatted properly (no colon to separate header and value)")
		}

		headers = make(map[string]string)
		rawHeaders := strings.Split(rawHeaders, ";")
		for _, header := range rawHeaders {
			var parts []string
			if strings.Contains(header, ": ") {
				parts = strings.Split(header, ": ")
			} else if strings.Contains(header, ":") {
				parts = strings.Split(header, ":")
			} else {
				continue
			}
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return nil
}
