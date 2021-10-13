package output

import (
	"bufio"
	"io"
	"net/url"
	"path"
	"strings"

	jsoniter "github.com/json-iterator/go"
)

type JSONResult struct {
	Url string `json:"url"`
}

func WriteURLs(results <-chan string, writer io.Writer, blacklistMap map[string]struct{}) []string {
	var resultlist []string
	_ = bufio.NewWriter(writer)
	for result := range results {
		if len(blacklistMap) != 0 {
			u, err := url.Parse(result)
			if err != nil {
				continue
			}
			base := strings.Split(path.Base(u.Path), ".")
			ext := base[len(base)-1]
			if ext != "" {
				_, ok := blacklistMap[strings.ToLower(ext)]
				if ok {
					continue
				}
			}
		}
		//fmt.Printf("ssssssssssssssss%v", result)
		resultlist = append(resultlist, result)
		
	}
	return resultlist
}
func WriteURLsJSON(results <-chan string, writer io.Writer, blacklistMap map[string]struct{}) {
	var jr JSONResult
	enc := jsoniter.NewEncoder(writer)
	for result := range results {
		if len(blacklistMap) != 0 {
			u, err := url.Parse(result)
			if err != nil {
				continue
			}
			base := strings.Split(path.Base(u.Path), ".")
			ext := base[len(base)-1]
			if ext != "" {
				_, ok := blacklistMap[strings.ToLower(ext)]
				if ok {
					continue
				}
			}
		}
		jr.Url = result
		enc.Encode(jr)
	}
}
