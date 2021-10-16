package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
	"regexp"
	"gourls/alienvault"
	"gourls/gau"
	"gourls/removeDup"
	"gourls/fprobe"
	"gourls/hakrawle"
	"gourls/writeresult"
	"gourls/urlhunter"
	"gourls/gospider"
)

var oneRun []string
var dateParam string
var fproberesultslist []string
var blacklists string
var urllists []string


func main() {

	var domains []string

	var dates bool
	var inputFile string
	var mode string
	var scanport string
	var url string
	flag.BoolVar(&dates, "dates", false, "show date of fetch in the first column")
	flag.StringVar(&url, "u", "", "url to scan em.: http://wwww.example.com")
	flag.StringVar(&scanport, "scanport", "", "scanport for urlgospiderURLs and hakrawleURLs em.: Large|Medium|XXlarge")
	flag.StringVar(&inputFile, "f", "domain.txt", "domain file")
	flag.StringVar(&blacklists, "blacklist", "(gov.cn|sentry.)", "blacklist em.:\"(gov.cn|sentry.)\"")
	flag.StringVar(&dateParam, "hunter", "urlteam_2021-10-07-21-17-02", "hunter dump file")
	

	var noSubs bool
	flag.BoolVar(&noSubs, "no-subs", false, "don't include subdomains of the target domain")
	flag.StringVar(&mode, "mode","",  `
1、getCommonCrawlURLs
2、alienURLs
3、GauURLs
4、urlhunterURLs
5、urlgospiderURLs
6、hakrawleURLs

Use to run .em: urlgospiderURLs or urlgospiderURLs,urlhunterURLs`)
	flag.Parse()

	if flag.NArg() > 0 {
		// fetch for a single domain
		domains = []string{flag.Arg(0)}
	} else {

		// fetch for all domains from stdin
		f, err := os.Open(inputFile)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Error when open input file: %s\n", err)
            os.Exit(1)
        }
        defer f.Close()
		var sc *bufio.Scanner
        sc = bufio.NewScanner(f)
		for sc.Scan() {
			domains = append(domains, strings.TrimSpace(sc.Text()))
		}

		if err := sc.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to read input: %s\n", err)
		}
	}

	if scanport !="" {
		for _, domain := range domains {
			fprobeURLs(domain,scanport)
		}
	}
	

	var modenames []string
	for _,modename := range strings.Split(strings.TrimSpace(mode), ","){
		modenames = append(modenames,modename)
	}
	
	fetchFns := []fetchFn{
		//getWaybackURLs,
		//getCommonCrawlURLs,
		//getVirusTotalURLs,
		//alienURLs,
		//GauURLs,
		//urlhunterURLs,
		//urlgospiderURLs,
		//hakrawleURLs,
	}
	for _,v := range modenames {
		if strings.TrimSpace(v) == "getCommonCrawlURLs"{
			fetchFns = append(fetchFns,getCommonCrawlURLs)
		}
		if strings.TrimSpace(v) == "GauURLs"{
			fetchFns = append(fetchFns,GauURLs)
		}
		if strings.TrimSpace(v) == "urlhunterURLs"{
			fetchFns = append(fetchFns,urlhunterURLs)
		}
		if strings.TrimSpace(v) == "alienURLs"{
			fetchFns = append(fetchFns,alienURLs)
		}
		if scanport != ""{
			fetchFns = append(fetchFns,savefprobeURLs)
		}
		if strings.Contains(url,"http"){
			urllists = append(urllists,url)
			fetchFns = append(fetchFns,urlgospiderURLs)
			fetchFns = append(fetchFns,hakrawleURLs)
			
		}
	}

	var writelist []string
	for _, domain := range domains {

		var wg sync.WaitGroup
		wurls := make(chan wurl)

		for _, fn := range fetchFns {
			wg.Add(1)
			fetch := fn
			go func() {
				defer wg.Done()
				resp, err := fetch(domain, noSubs)
				if err != nil {
					return
				}
				for _, r := range resp {
					if noSubs && isSubdomain(r.url, domain) {
						continue
					}
					wurls <- r
				}
			}()
		}

		go func() {
			wg.Wait()
			close(wurls)
		}()

		seen := make(map[string]bool)

		
		for w := range wurls {
			if _, ok := seen[w.url]; ok {
				continue
			}
			seen[w.url] = true

			if dates {

				d, err := time.Parse("20060102150405", w.date)
				if err != nil {
					fmt.Fprintf(os.Stderr, "failed to parse date [%s] for URL [%s]\n", w.date, w.url)
				}

				fmt.Printf("%s %s \n", d.Format(time.RFC3339), w.url)
				writelist = append(writelist,w.url)
			} else {
				fmt.Printf("%v\n",w.url)
				writelist = append(writelist,w.url)
			}
		}
		
	}
	writeresult.Writeresult(removeDup.RemoveDup(writelist))

}

type wurl struct {
	date string
	url  string
}

type fetchFn func(string, bool) ([]wurl, error)

func getWaybackURLs(domain string, noSubs bool) ([]wurl, error) {
	subsWildcard := "*."
	if noSubs {
		subsWildcard = ""
	}

	res, err := http.Get(
		fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=%s%s/*&output=json&collapse=urlkey", subsWildcard, domain),
	)
	if err != nil {
		return []wurl{}, err
	}

	raw, err := ioutil.ReadAll(res.Body)

	res.Body.Close()
	if err != nil {
		return []wurl{}, err
	}

	var wrapper [][]string
	err = json.Unmarshal(raw, &wrapper)

	out := make([]wurl, 0, len(wrapper))

	skip := true
	for _, urls := range wrapper {
		// The first item is always just the string "original",
		// so we should skip the first item
		if skip {
			skip = false
			continue
		}
		out = append(out, wurl{date: urls[1], url: urls[2]})
	}

	return out, nil

}

func getCommonCrawlURLs(domain string, noSubs bool) ([]wurl, error) {
	subsWildcard := "*."
	if noSubs {
		subsWildcard = ""
	}
	fmt.Printf("%v", "use getCommonCrawlURLs scan.....\n")
	res, err := http.Get(
		fmt.Sprintf("https://index.commoncrawl.org/CC-MAIN-2021-39-index?url=%s%s/*&output=json", subsWildcard, domain),
	)
	if err != nil {
		return []wurl{}, err
	}

	defer res.Body.Close()
	sc := bufio.NewScanner(res.Body)

	out := make([]wurl, 0)
	var urlslist []string
	for sc.Scan() {

		wrapper := struct {
			URL       string `json:"url"`
			Timestamp string `json:"timestamp"`
		}{}
		err = json.Unmarshal([]byte(sc.Text()), &wrapper)

		if err != nil {
			continue
		}
		

		urlslist = append(urlslist, wrapper.URL)

		for _, u := range removeDup.RemoveDup(urlslist) {
			out = append(out, wurl{date: wrapper.Timestamp, url: u})
		}	
		
	}

	return out, nil

}

func getVirusTotalURLs(domain string, noSubs bool) ([]wurl, error) {
	out := make([]wurl, 0)

	apiKey := os.Getenv("VT_API_KEY")
	if apiKey == "" {
		// no API key isn't an error,
		// just don't fetch
		return out, nil
	}

	fetchURL := fmt.Sprintf(
		"https://www.virustotal.com/vtapi/v2/domain/report?apikey=%s&domain=%s",
		apiKey,
		domain,
	)

	resp, err := http.Get(fetchURL)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()

	wrapper := struct {
		URLs []struct {
			URL string `json:"url"`
			// TODO: handle VT date format (2018-03-26 09:22:43)
			//Date string `json:"scan_date"`
		} `json:"detected_urls"`
	}{}

	dec := json.NewDecoder(resp.Body)

	err = dec.Decode(&wrapper)
	

	var urlslist []string
	for _, u := range wrapper.URLs {
		urlslist = append(urlslist, u.URL)
	}
	for _, u := range removeDup.RemoveDup(urlslist) {
		out = append(out, wurl{url: u})
	}

	
	return out,nil

}

func alienURLs(domain string, noSubs bool) ([]wurl, error) {
	fmt.Printf("%v", "use alienURLs scan.....\n")
	out := make([]wurl, 0)
	pattern := `(?i)^?(?:\w+\.)*?(\w*\.(?:com\.cn|cn|com|net))`
	pattern = strings.Replace(pattern, `\<`, `\b`, -1)
	flysnowRegexp := regexp.MustCompile(pattern)
	onedomain := flysnowRegexp.FindStringSubmatch(domain)
	if len(onedomain)==0 {
		return out,nil	
	}
	
	if writeresult.Domainin("alien" + onedomain[len(onedomain)-1],oneRun){
		return out,nil
	}
	fmt.Printf("%v", "use alienurl scan.....\n")
	oneRun = append(oneRun,"alien" + onedomain[len(onedomain)-1])
	alienvaultresult := alienvault.Alienvault(onedomain[len(onedomain)-1])
	
	
	for _, u := range removeDup.RemoveDup(alienvaultresult) {
		out = append(out, wurl{url: u})
	}
	return out,nil
}

func GauURLs(domain string, noSubs bool) ([]wurl, error) {
	out := make([]wurl, 0)
	pattern := `(?i)^?(?:\w+\.)*?(\w*\.(?:com\.cn|cn|com|net))`
	pattern = strings.Replace(pattern, `\<`, `\b`, -1)
	flysnowRegexp := regexp.MustCompile(pattern)
	onedomain := flysnowRegexp.FindStringSubmatch(domain)
	if len(onedomain)==0 {
		return out,nil	
	}

	if writeresult.Domainin("gau" + onedomain[len(onedomain)-1],oneRun){
		return out,nil
	}
	fmt.Printf("%v", "use gau scan.....\n")
	oneRun = append(oneRun,"gau" + onedomain[len(onedomain)-1])
	resultslist := gau.Gau(onedomain[len(onedomain)-1])
	for _, u := range removeDup.RemoveDup(resultslist) {
		out = append(out, wurl{url: u})
	}
	return out,nil
}



func fprobeURLs(domain string,scanport string) {
	resultslist := fprobe.Fprobe(domain,scanport)
	fproberesultslist = removeDup.RemoveDup(append(fproberesultslist,resultslist...))
}

func savefprobeURLs(domain string, noSubs bool) ([]wurl, error){
	out := make([]wurl, 0)
	for _, u := range removeDup.RemoveDup(fproberesultslist) {
		out = append(out, wurl{url: u})
	}
	return out,nil
}

func hakrawleURLs(domain string, noSubs bool) ([]wurl, error){
	out := make([]wurl, 0)
	var resultslist2 []string

	for _, u := range removeDup.RemoveDup(urllists) {
		resulthakrawlelist := hakrawle.Hakrawle(u)
		resultslist2 = append(resultslist2,resulthakrawlelist...)
	}
	for _, u := range removeDup.RemoveDup(resultslist2) {
		out = append(out, wurl{url: u})
	}
	return out,nil
}

func urlhunterURLs(domain string, noSubs bool) ([]wurl, error){
	fmt.Printf("%v", "use urlhunterURLs scan.....\n")
	out := make([]wurl, 0)
	pattern := `(?i)^?(?:\w+\.)*?(\w*\.(?:com\.cn|cn|com|net))`
	pattern = strings.Replace(pattern, `\<`, `\b`, -1)
	flysnowRegexp := regexp.MustCompile(pattern)
	onedomain := flysnowRegexp.FindStringSubmatch(domain)
	if len(onedomain)==0 {
		return out,nil	
	}
	
	if writeresult.Domainin("hunter" + onedomain[len(onedomain)-1],oneRun){
		return out,nil
	}
	oneRun = append(oneRun,"hunter" + onedomain[len(onedomain)-1])
	urlhunterURLlist := urlhunter.Urlhunter(onedomain[len(onedomain)-1],dateParam)
	for _, u := range removeDup.RemoveDup(urlhunterURLlist) {
		out = append(out, wurl{url: u})
	}
	return out,nil
}


func urlgospiderURLs(domain string, noSubs bool) ([]wurl, error){ 
	fmt.Printf("%v", "use urlgospiderURLs scan.....\n")
	out := make([]wurl, 0)
	
	var resultslist2 []string
	gospiderresultslist := gospider.Gospider(urllists,blacklists)
	resultslist2 = append(resultslist2,gospiderresultslist...)
	
	for _, u := range resultslist2 {
		out = append(out, wurl{url: u})
	}
	return out,nil
}


func isSubdomain(rawUrl, domain string) bool {
	u, err := url.Parse(rawUrl)
	if err != nil {
		// we can't parse the URL so just
		// err on the side of including it in output
		return false
	}

	return strings.ToLower(u.Hostname()) != strings.ToLower(domain)
}

func getVersions(u string) ([]string, error) {
	out := make([]string, 0)

	resp, err := http.Get(fmt.Sprintf(
		"http://web.archive.org/cdx/search/cdx?url=%s&output=json", u,
	))

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

		// skip the first element, it's the field names
		if first {
			first = false
			continue
		}

		// fields: "urlkey", "timestamp", "original", "mimetype", "statuscode", "digest", "length"
		if seen[s[5]] {
			continue
		}
		seen[s[5]] = true
		out = append(out, fmt.Sprintf("https://web.archive.org/web/%sif_/%s", s[1], s[2]))
	}

	return out, nil
}
