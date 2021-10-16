# gourls 
端口扫描，获取url包括参数，参考优秀项目，感谢THANKS：

[gau](https://github.com/lc/gau)

[gosipider](https://github.com/jaeles-project/gospider)

[fprobe](https://github.com/theblackturtle/fprobe)

[hakrawler](https://github.com/hakluke/hakrawler)

[urlhunter](https://github.com/utkusen/urlhunter)



#### 使用:
Examples:




```bash
gourls.exe -h
```
#
```
Usage of C:\gotest\src\gourls\gourls.exe:
  -blacklist string
        blacklist em.:"(gov.cn|sentry.)" (default "(gov.cn|sentry.)")
  -dates
        show date of fetch in the first column
  -f string
        domain file (default "domain.txt")
  -hunter string
        hunter dump file (default "urlteam_2021-10-07-21-17-02")
  -mode string

        1、getCommonCrawlURLs
        2、alienURLs
        3、GauURLs
        4、urlhunterURLs
        5、urlgospiderURLs
        6、hakrawleURLs

        Use to run .em: urlgospiderURLs or urlgospiderURLs,urlhunterURLs
  -no-subs
        don't include subdomains of the target domain
  -scanport string
        scanport for urlgospiderURLs and hakrawleURLs em.: Large|Medium|XXlarge
  -u string
        url to scan em.: http://wwww.example.com
```

#
#### 常用参数：
- 端口扫描：
```
gourls.exe -f domain.txt -scanport Medium
```
#
- url模式：
```
gourls.exe -u http://wwww.example.com
```
#
- api模式：
```
gourls.exe -f domain.txt -mode GauURLs,alienURLs
```



#
如果使用urlgospiderURLs模块，需要(翻墙)访问：
https://archive.org/services/search/v1/scrape?debug=false&xvar=production&total_only=false&count=10000&fields=identifier%2Citem_size&q=Urlteam%20Release

选择字段，如：urlteam_2021-10-07-21-17-02
拼接成url：https://archive.org/download/urlteam_2021-10-07-21-17-02

新建archives目录，并建一个选择字段的目录，如：urlteam_2021-10-07-21-17-02，下载文件放到 urlteam_2021-10-07-21-17-02 下即可



点击下载
[releases](https://github.com/hacden/gourls/releases)
