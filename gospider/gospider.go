package gospider

import (
	"fmt"
	jsoniter "github.com/json-iterator/go"
	"io/ioutil"
	"net/url"
	"strings"
	"sync"

	"gourls/gospider/core"

	"github.com/sirupsen/logrus"

)


func Gospider(sites []string) []string{


	// commands.Flags().StringP("sites", "S", "", "Site list to crawl")
	// commands.Flags().StringP("proxy", "", "", "Proxy (Ex: http://127.0.0.1:8080)")
	// commands.Flags().StringP("output", "o", "", "Output folder")
	// commands.Flags().StringP("user-agent", "u", "web", "User Agent to use\n\tweb: random web user-agent\n\tmobi: random mobile user-agent\n\tor you can set your special user-agent")
	// commands.Flags().StringP("cookie", "", "", "Cookie to use (testA=a; testB=b)")
	// commands.Flags().StringArrayP("header", "H", []string{}, "Header to use (Use multiple flag to set multiple header)")
	// commands.Flags().StringP("burp", "", "", "Load headers and cookie from burp raw http request")
	// commands.Flags().StringP("blacklist", "", "", "Blacklist URL Regex")
	// commands.Flags().StringP("whitelist", "", "", "Whitelist URL Regex")
	// commands.Flags().StringP("whitelist-domain", "", "", "Whitelist Domain")
    // commands.Flags().StringP("filter-length", "L", "", "Turn on length filter")

	// commands.Flags().IntP("threads", "t", 1, "Number of threads (Run sites in parallel)")
	// commands.Flags().IntP("concurrent", "c", 5, "The number of the maximum allowed concurrent requests of the matching domains")
	// commands.Flags().IntP("depth", "d", 1, "MaxDepth limits the recursion depth of visited URLs. (Set it to 0 for infinite recursion)")
	// commands.Flags().IntP("delay", "k", 0, "Delay is the duration to wait before creating a new request to the matching domains (second)")
	// commands.Flags().IntP("random-delay", "K", 0, "RandomDelay is the extra randomized duration to wait added to Delay before creating a new request (second)")
	// commands.Flags().IntP("timeout", "m", 10, "Request timeout (second)")

	// commands.Flags().BoolP("base", "B", false, "Disable all and only use HTML content")
	// commands.Flags().BoolP("js", "", true, "Enable linkfinder in javascript file")
	// commands.Flags().BoolP("sitemap", "", false, "Try to crawl sitemap.xml")
	// commands.Flags().BoolP("robots", "", true, "Try to crawl robots.txt")
	// commands.Flags().BoolP("other-source", "a", false, "Find URLs from 3rd party (Archive.org, CommonCrawl.org, VirusTotal.com, AlienVault.com)")
	// commands.Flags().BoolP("include-subs", "w", false, "Include subdomains crawled from 3rd party. Default is main domain")
	// commands.Flags().BoolP("include-other-source", "r", false, "Also include other-source's urls (still crawl and request)")
    // commands.Flags().BoolP("subs", "", false, "Include subdomains")

	// commands.Flags().BoolP("debug", "", false, "Turn on debug mode")
	// commands.Flags().BoolP("json", "", false, "Enable JSON output")
	// commands.Flags().BoolP("verbose", "v", false, "Turn on verbose")
	// commands.Flags().BoolP("quiet", "q", false, "Suppress all the output and only show URL")
	// commands.Flags().BoolP("no-redirect", "", false, "Disable redirect")
	// commands.Flags().BoolP("version", "", false, "Check version")
    // commands.Flags().BoolP("length", "l", false, "Turn on length")
    // commands.Flags().BoolP("raw", "R", false, "Enable raw output")

	base := false
	verbose := false
	isDebug := false
	linkfinder := true
	robots := true
	otherSource := false
	includeSubs := false
	includeOtherSourceResult := false
	threads := 200
	sitemap := false

	core.Logger.SetLevel(logrus.InfoLevel)
	
	if !verbose && !isDebug {
		core.Logger.SetOutput(ioutil.Discard)
	}

	// Parse sites input
	var siteList []string

	if len(sites) > 0 {
		siteList = append(siteList, sites...)
	}else{
		return core.Gospiderlist
	}
	

	if base {
		linkfinder = false
		robots = false
		otherSource = false
		includeSubs = false
		includeOtherSourceResult = false
	}

	var wg sync.WaitGroup
	inputChan := make(chan string, threads)
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for rawSite := range inputChan {
				site, err := url.Parse(rawSite)
				if err != nil {
					logrus.Errorf("Failed to parse %s: %s", rawSite, err)
					continue
				}

				var siteWg sync.WaitGroup

				crawler := core.NewCrawler(site)
				siteWg.Add(1)
				go func() {
					defer siteWg.Done()
					crawler.Start(linkfinder)
				}()

				// Brute force Sitemap path
				if sitemap {
					siteWg.Add(1)
					go core.ParseSiteMap(site, crawler, crawler.C, &siteWg)
				}

				// Find Robots.txt
				if robots {
					siteWg.Add(1)
					go core.ParseRobots(site, crawler, crawler.C, &siteWg)
				}

				if otherSource {
					siteWg.Add(1)
					go func() {
						defer siteWg.Done()
						urls := core.OtherSources(site.Hostname(), includeSubs)
						for _, url := range urls {
							url = strings.TrimSpace(url)
							if len(url) == 0 {
								continue
							}

							outputFormat := fmt.Sprintf("[other-sources] - %s", url)
							if includeOtherSourceResult {
								if crawler.JsonOutput {
									sout := core.SpiderOutput{
										Input:      crawler.Input,
										Source:     "other-sources",
										OutputType: "url",
										Output:     url,
									}
									if data, err := jsoniter.MarshalToString(sout); err == nil {
										outputFormat = data
									}
								} else if crawler.Quiet {
									outputFormat = url
								}
								fmt.Println(outputFormat)

								if crawler.Output != nil {
									crawler.Output.WriteToFile(outputFormat)
								}
							}

							_ = crawler.C.Visit(url)
						}
					}()
				}
				siteWg.Wait()
				crawler.C.Wait()
				crawler.LinkFinderCollector.Wait()
			}
		}()
	}

	for _, site := range siteList {
		inputChan <- site
	}
	close(inputChan)
	wg.Wait()
	core.Logger.Info("Done.")
	return core.Gospiderlist
}