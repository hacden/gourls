package fprobe

import (
    "crypto/sha1"
    "crypto/tls"
    "fmt"
    "net"
    "os"
    "regexp"
    "sort"
    "strings"
    "time"
    "github.com/3th1nk/cidr"
    "github.com/json-iterator/go"
    "github.com/panjf2000/ants/v2"
    "github.com/valyala/fasthttp"

    "sync"
    "github.com/emirpasic/gods/sets/treeset"
    "crypto/md5"
	"encoding/hex"
    
)

var (
    md5resplist []string 
    client          *fasthttp.Client
    similarDetector *Similar
    timeout         time.Duration
    urlRegex        = regexp.MustCompile(`^(http|ws)s?://`)

    portMedium = []string{"443","80","7000","7001","7002","7003","7004","7005","7006","7007","7008","7009","7010","7011","7012","7013","7014","7015","7016","7018","7020","7026","7070","7077","7080","7081","7082","7083","7088","7097","7100","7103","7106","7200","7443","7676","7741","7777","7778","7800","7999","8000","8001","8002","8003","8005","8006","8007","8008","8009","8010","8011","8020","8060","8070","8077","8078","8080","8081","8082","8083","8084","8085","8086","8087","8088","8089","8090","8091","8092","8093","8096","8099","8100","8101","8106", "8443"}
    portLarge  = []string{"81", "80","443","8000", "8001", "8008", "8080","8443"}
    portXlarge = []string{"81", "300", "591", "593", "832", "981", "1010", "1311", "2082", "2087", "2095", "2096", "2480", "3000", "3128", "3333", "4243", "4567", "4711", "4712", "4993", "5000", "5104", "5108", "5800", "6543", "7000", "7396", "7474", "8000", "8001", "8008", "8014", "8042", "8069", "8080", "8081", "8088", "8090", "8091", "8118", "8123", "8172", "8222", "8243", "8280", "8281", "8333", "8443", "8500", "8834", "8880", "8888", "8983", "9000", "9043", "9060", "9080", "9090", "9091", "9200", "9443", "9800", "9981", "12443", "16080", "18091", "18092", "20720", "28017"}
    portXXlarge = []string{"80","81","82","83","84","85","86","87","88","89","90","443","591","888","2082","2087","2095","2096","3000","3128","3443","4040","5443","5901","5902","5906","5907","5908","5909","5200","5201","6060","6082","6443","6500","6551","6558","6901","7000","7001","7002","7003","7004","7005","7006","7007","7008","7009","7010","7011","7012","7013","7014","7015","7016","7018","7019","7020","7021","7022","7023","7024","7025","7026","7070","7077","7080","7081","7082","7083","7088","7097","7100","7103","7106","7200","7201","7388","7402","7435","7443","7485","7496","7510","7512","7625","7627","7676","7741","7777","7778","7800","7911","7920","7921","7937","7938","7999","8000","8001","8002","8003","8005","8006","8007","8008","8009","8010","8011","8020","8021","8022","8025","8026","8031","8042","8045","8060","8070","8077","8078","8080","8081","8082","8083","8084","8085","8086","8087","8088","8089","8090","8091","8092","8093","8096","8099","8100","8101","8106","8134","8139","8180","8181","8192","8193","8194","8200","8222","8254","8290","8291","8292","8300","8333","8334","8336","8383","8400","8402","8443","8444","8485","8500","8553","8600","8649","8651","8652","8654","8663","8686","8701","8800","8873","8880","8881","8882","8888","8889","8899","8983","8994","8999","9000","9001","9002","9003","9009","9010","9011","9012","9021","9023","9027","9037","9040","9043","9050","9071","9080","9081","9082","9086","9090","9091","9099","9100","9101","9102","9103","9110","9111","9180","9200","9201","9205","9207","9208","9209","9210","9211","9212","9213","9220","9290","9332","9415","9418","9443","9485","9500","9502","9503","9535","9553","9575","9593","9594","9595","9618","9663","9666","9876","9877","9878","9898","9900","9908","9916","9917","9918","9919","9928","9929","9939","9943","9944","9968","9998","9999","10000","10001","10002","10003","10004","10009","10010","10012","10024","10025","10051","10080","10082","10086","10180","10215","10243","10250","10443","10566","10616","10617","10621","10626","10628","10629","10778","11110","11111","11211","11967","12000","12174","12265","12345","12601","13456","13722","13782","13783","14000","14238","14441","14442","15000","15001","15002","15003","15004","15660","15672","15742","16000","16001","16012","16016","16018","16080","16113","16992","16993","17877","17988","18040","18080","18100","18101","18800","18801","18803","18980","18983","18988","19101","19283","19315","19350","19780","19801","19842","20000","20005","20031","20221","20222","20828","21571","22222","22345","22939","23502","24444","24800","25734","25735","26214","27000","27017","27352","27353","27355","27356","27715","28080","28201","31021","32000","50070"}

)

type probeArgs []string





type Similar struct {
    hashs *treeset.Set
    mux   sync.Mutex
}

func NewSimilar() *Similar {
    return &Similar{
        hashs: treeset.NewWithStringComparator(),
    }
}

// Return true if add success (different site)
func (s *Similar) Add(hash string) bool {
    s.mux.Lock()
    bSize := s.hashs.Size()
    s.hashs.Add(hash)
    aSize := s.hashs.Size()
    s.mux.Unlock()
    return aSize > bSize
}


func (p *probeArgs) Set(val string) error {
    *p = append(*p, val)
    return nil
}

func (p probeArgs) String() string {
    return strings.Join(p, ",")
}

type verboseStruct struct {
    Site        string `json:"site"`
    StatusCode  int    `json:"status_code"`
    Server      string `json:"server"`
    ContentType string `json:"content_type"`
    Location    string `json:"location"`
}

type Task struct {
    Scheme string
    Url    string
}

func (t *Task) String() string {
    return fmt.Sprintf("%s://%s", t.Scheme, t.Url)
}

func init() {
    client = &fasthttp.Client{
        NoDefaultUserAgentHeader: true,
        Dial: func(addr string) (net.Conn, error) {
            return fasthttp.DialDualStackTimeout(addr, time.Minute*3) // net/http's default is 3 minutes
        },
        TLSConfig: &tls.Config{
            InsecureSkipVerify: true,
            Renegotiation:      tls.RenegotiateOnceAsClient, // For "local error: tls: no renegotiation"
        },
        // This also limits the maximum header size.
        ReadBufferSize:      48 * 1024,
        WriteBufferSize:     48 * 1024,
        MaxIdleConnDuration: time.Second,
    }
}

func Fprobe(domain string,portlx string) []string{
    var resultlists []string

    // Threads
    var concurrency int
    concurrency = 100

    // probe flags, get from httprobe
    var probes probeArgs
    probes = append(probes,portlx)
    
    // skip default probes flag, get from httprobe
    var skipDefault bool
    skipDefault = false

    // Time out flag
    var to int
    to = 6
    var sameLinePorts bool
    sameLinePorts =false
    //flag.BoolVar(&sameLinePorts, "l", false, "Use ports in the same line (google.com,2087,2086)")

    var cidrInput bool
    cidrInput =false
    //flag.BoolVar(&cidrInput, "cidr", false, "Generate IP addresses from CIDR")

    // Get an idea from httprobe written by @tomnomnom
    var preferHTTPS bool
    preferHTTPS =false
    //flag.BoolVar(&preferHTTPS, "prefer-https", false, "oOnly try plain HTTP if HTTPS fails")

    var detectSimilarSites bool
    detectSimilarSites =false
    //flag.BoolVar(&detectSimilarSites, "detect-similar", false, "Detect similar sites (careful when using this, this just using headers and cookies to generation hash)")

    var verbose bool
    verbose = false  
    //flag.BoolVar(&verbose, "v", false, "Turn on verbose")

    var debug bool
    debug =false
    //flag.BoolVar(&debug, "d", false, "Turn on debug")


    timeout = time.Duration(to) * time.Second
    if detectSimilarSites {
        similarDetector = NewSimilar()
    }

    var wg sync.WaitGroup
    var workingPool *ants.PoolWithFunc
    workingPool, err := ants.NewPoolWithFunc(concurrency, func(i interface{}) {
        defer wg.Done()
        t := i.(Task)
        success, v, err := isWorking(t.String(), verbose)
        if success {
            if !verbose {
                resultlists = append(resultlists, t.String() + "/")
                fmt.Printf("%v\n", t.String())
            } else {
                if vj, err := jsoniter.MarshalToString(v); err == nil {
                    fmt.Println(vj)
                }
            }
            if (preferHTTPS && t.Scheme == "https") || t.Scheme == "http" {
                return
            }
            wg.Add(1)
            workingPool.Invoke(Task{
                Scheme: "http",
                Url:    t.Url,
            })
        } else {
            if debug {
                fmt.Fprintf(os.Stderr, "[DEBUG] %s: %s\n", t.String(), err)
            }
        }

    }, ants.WithPreAlloc(true))
    if err != nil {
        fmt.Println("Failed to create working pool")
        os.Exit(1)
    }
    defer workingPool.Release()

    var sc []string
    
    sc = append(sc, domain)
   

    for _, u := range sc{
        line := strings.TrimSpace(u)
        if line == "" {
            continue
        }

        if cidrInput {
            c, err := cidr.ParseCIDR(line)
            if err != nil {
                fmt.Fprintf(os.Stderr, "Failed to parse input as CIDR: %s\n", err)
                continue
            }
            if err := c.ForEachIP(func(ip string) error {
                wg.Add(1)
                _ = workingPool.Invoke(Task{
                    Scheme: "https",
                    Url:    ip,
                })
                return nil
            }); err != nil {
                fmt.Fprintf(os.Stderr, "Failed to parse input as CIDR: %s\n", err)
            }
            continue
        }

        if sameLinePorts {
            lineArgs := strings.Split(line, ",")
            if len(lineArgs) < 2 {
                continue
            }
            d, ports := lineArgs[0], lineArgs[1:]
            for _, port := range ports {
                if port := strings.TrimSpace(port); port != "" {
                    wg.Add(1)
                    _ = workingPool.Invoke(Task{
                        Scheme: "https",
                        Url:    fmt.Sprintf("%s:%s", d, port),
                    })
                }
            }
            continue
        }

        if urlRegex.MatchString(line) {
            wg.Add(1)
            if strings.HasPrefix(line, "http://") {
                _ = workingPool.Invoke(Task{
                    Scheme: "http",
                    Url:    strings.TrimPrefix(line, "http://"),
                })
            } else {
                _ = workingPool.Invoke(Task{
                    Scheme: "https",
                    Url:    strings.TrimPrefix(line, "http://"),
                })
            }
            continue
        }

        if !skipDefault {
            wg.Add(1)
            _ = workingPool.Invoke(Task{
                Scheme: "https",
                Url:    line,
            })
        }

        for _, p := range probes {
            switch p {
            case "medium":
                for _, port := range portMedium {
                    wg.Add(1)
                    _ = workingPool.Invoke(Task{
                        Scheme: "https",
                        Url:    fmt.Sprintf("%s:%s", line, port),
                    })
                }
            case "large":
                for _, port := range portLarge {
                    wg.Add(1)
                    _ = workingPool.Invoke(Task{
                        Scheme: "https",
                        Url:    fmt.Sprintf("%s:%s", line, port),
                    })
                }
            case "xlarge":
                for _, port := range portXlarge {
                    wg.Add(1)
                    _ = workingPool.Invoke(Task{
                        Scheme: "https",
                        Url:    fmt.Sprintf("%s:%s", line, port),
                    })
                }
            case "xxlarge":
                for _, port := range portXXlarge {
                    wg.Add(1)
                    _ = workingPool.Invoke(Task{
                        Scheme: "https",
                        Url:    fmt.Sprintf("%s:%s", line, port),
                    })
                }

            default:
                pair := strings.SplitN(p, ":", 2)
                if len(pair) != 2 {
                    continue
                }
                wg.Add(1)
                if pair[0] == "http" {
                    _ = workingPool.Invoke(Task{
                        Scheme: "http",
                        Url:    fmt.Sprintf("%s:%s", line, pair[1]),
                    })
                } else {
                    _ = workingPool.Invoke(Task{
                        Scheme: "https",
                        Url:    fmt.Sprintf("%s:%s", line, pair[1]),
                    })
                }
            }
        }
    }
    wg.Wait()
    return resultlists
}


func md5Str(origin string) string {
	m := md5.New()
	m.Write([]byte(origin))
	
    return string(hex.EncodeToString(m.Sum(nil)))
}


func isWorking(url string, verbose bool) (bool, *verboseStruct, error) {
    var v *verboseStruct
    req := fasthttp.AcquireRequest()
    defer fasthttp.ReleaseRequest(req)
    req.SetRequestURI(url)
    req.SetConnectionClose()

    resp := fasthttp.AcquireResponse()
    defer fasthttp.ReleaseResponse(resp)

    resp.SkipBody = false
    
 

    err := client.DoTimeout(req, resp, timeout)
    if err != nil {
        return false, v, err
    }

    if similarDetector != nil {
        var headers []string
        resp.Header.VisitAll(func(key, _ []byte) {
            headers = append(headers, string(key))
        })
        sort.Strings(headers)

        var cookies []string
        resp.Header.VisitAllCookie(func(key, _ []byte) {
            cookies = append(cookies, string(key))
        })
        sort.Strings(cookies)
        hash := getHash(headers, cookies)
        // Return if this site's hash exists
        if !similarDetector.Add(hash) {
            return false, v, fmt.Errorf("similar another site")
        }
    }

    if verbose {
        server := resp.Header.Peek(fasthttp.HeaderServer)
        contentType := resp.Header.Peek(fasthttp.HeaderContentType)
        location := resp.Header.Peek(fasthttp.HeaderLocation)

        

        v = &verboseStruct{
            Site:        url,
            StatusCode:  resp.StatusCode(),
            Server:      string(server),
            ContentType: string(contentType),
            Location:    string(location),
        }
    }
    return true, v, nil
}

func getHash(headers, cookies []string) string {
    headerHash := strings.Join(headers, ",")
    cookieHash := strings.Join(cookies, ",")
    hash := fmt.Sprintf("%s,%s", headerHash, cookieHash)
    checksum := sha1.Sum([]byte(hash))
    return fmt.Sprintf("%x", checksum)
}
