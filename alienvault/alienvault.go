package alienvault

import (
	"fmt"
	"github.com/bitly/go-simplejson"
	"io/ioutil"
	"net/http"
	"time"
	

)

var results []string

func getRequest(url string) string{

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("alienault: %v",err)
		return "is_not_ok"
	}
	defer resp.Body.Close()
	result, _ := ioutil.ReadAll(resp.Body)
	return string(result)

}



func Alienvault(domain string) []string {
	
	url := "https://otx.alienvault.com/api/v1/indicators/domain/"+ domain+"/url_list?limit=1000&page=1"
	result := getRequest(url)
	if result == "is_not_ok"{
		return results
	}
	res,_:= simplejson.NewJson([]byte(result))
	for i,_ := range result{
		u,err:=res.Get("url_list").GetIndex(i).Get("url").String()
		if err == nil{
			results = append(results, u)
		}

	}
	return results
}
