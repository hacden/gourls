package urlhunter

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/fatih/color"
	"os/exec"

)

var baseurl string = "https://archive.org/services/search/v1/scrape?debug=false&xvar=production&total_only=false&count=10000&fields=identifier%2Citem_size&q=Urlteam%20Release"

type Files struct {
	XMLName xml.Name `xml:"files"`
	Text    string   `xml:",chardata"`
	File    []struct {
		Text     string `xml:",chardata"`
		Name     string `xml:"name,attr"`
		Source   string `xml:"source,attr"`
		Mtime    string `xml:"mtime"`
		Size     string `xml:"size"`
		Md5      string `xml:"md5"`
		Crc32    string `xml:"crc32"`
		Sha1     string `xml:"sha1"`
		Format   string `xml:"format"`
		Btih     string `xml:"btih"`
		DumpType string `xml:name,attr`
	} `xml:"file"`
}

var outresultlist []string

func Urlhunter(domain string,dateParam string) []string{
	//dateParam := "urlteam_2021-10-07-21-17-02"
	
	if strings.Trim(domain,"") == ""{
		return outresultlist	
	}
	getArchive(dateParam, domain)
	
	color.Green("Search complete!")

	return outresultlist
}

func getArchive(fullname string, domain string) {
	fmt.Println("Search starting for: " + fullname)
	
	dumpFiles := archiveMetadata(fullname)

	for _, item := range dumpFiles.File {
		if fileExists(filepath.Join("archives", fullname, item.Name)) == false {
			color.Red(item.Name + " doesn't exist locally.")
			url1 := "https://archive.org/download/" + fullname + "/" + item.Name
			fmt.Printf("Download zip to: %v", url1)
			os.Exit(1)
		}
		if fileExists(filepath.Join("archives", fullname, item.DumpType)) !=false{
			break
		}
		color.Magenta("Unzipping: " + item.Name)
		_, err := Unzip(filepath.Join("archives", fullname, item.Name), filepath.Join("archives", fullname))
		if err != nil {
			panic(err)
		}
	}

	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		panic(err)
	}

	//将\替换成/
	exedir := strings.Replace(dir, "\\", "/", -1)  + "/"
	color.Cyan("Decompressing XZ Archives..")
	for _, item := range dumpFiles.File {
		
		fmt.Printf("unzip to: %v", filepath.Join(exedir,"archives", fullname, item.DumpType + "\n"))
		tarfile, _ := filepath.Glob(filepath.Join("archives", fullname, item.DumpType, "*.txt.xz"))
		
		outrun ,_:= filepath.Glob(filepath.Join("archives", fullname, item.DumpType, "*.txt"))
		if len(outrun) != 0{
			break
		}

		_, err := exec.Command("xz/xz.exe", "--decompress", tarfile[0]).Output()
		if err != nil {
			fmt.Println(err)
			panic(err)
		}
	}
	
	for _, item := range dumpFiles.File {
		
		dump_path, _ := filepath.Glob(filepath.Join("archives", fullname, item.DumpType, "*.txt"))

		if len(dump_path)==0{
			continue
		}
		fmt.Println("\nSearching: " + domain + " in: " + dump_path[0])
		searchFile(dump_path[0], domain)
	}

}

func searchFile(fileLocation string, domain string) {

	keyword := "regex "+domain
	f, err := os.Open(fileLocation)
	scanner := bufio.NewScanner(f)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	if strings.HasPrefix(keyword, "regex") {
		regexValue := strings.Split(keyword, " ")[1]
		r, err := regexp.Compile(regexValue)
		if err != nil {
			color.Red("Invalid Regex!")
			return
		}
		for scanner.Scan() {
			if r.MatchString(scanner.Text()) {
				textToWrite := strings.Split(scanner.Text(), "|")[1]
				fmt.Printf("%v\n", textToWrite)
				outresultlist = append(outresultlist, textToWrite)
			}
		}
	} else {
		if strings.Contains(keyword, ",") {
			keywords := strings.Split(keyword, ",")
			for scanner.Scan() {
				foundFlag := true
				for i := 0; i < len(keywords); i++ {
					if bytes.Contains(scanner.Bytes(), []byte(keywords[i])) {
						continue
					} else {
						foundFlag = false
					}
				}
				if foundFlag == true {
					textToWrite := strings.Split(scanner.Text(), "|")[1]
					fmt.Printf("%v\n", textToWrite)
					outresultlist = append(outresultlist, textToWrite)
				}
			}

		} else {
			toFind := []byte(keyword)
			for scanner.Scan() {
				if bytes.Contains(scanner.Bytes(), toFind) {
					textToWrite := strings.Split(scanner.Text(), "|")[1]
					fmt.Printf("%v\n", textToWrite)
					outresultlist = append(outresultlist, textToWrite)
				}
			}
		}
	}

}

func ifArchiveExists(fullname string) bool {
	dumpFiles := archiveMetadata(fullname)
	for _, item := range dumpFiles.File {
		archiveFilepaths, err := filepath.Glob(filepath.Join("archives", fullname, item.DumpType, "*.txt"))
		if len(archiveFilepaths) == 0 || err != nil {
			return false
		}
	}
	return true
}

func archiveMetadata(fullname string) Files {
	metadataFilename := "urlteam_" + strings.Split(fullname, "_")[1] + "_files.xml"
	if fileExists("archives/"+fullname+"/"+metadataFilename) == false {
		color.Red(metadataFilename + " doesn't exists locally.")
		metadataUrl := "https://archive.org/download/" + fullname + "/" + metadataFilename
		fmt.Printf("Download to: %v\n", metadataUrl)
	}
	byteValue, _ := ioutil.ReadFile("archives/" + fullname + "/" + metadataFilename)
	files := Files{}
	xml.Unmarshal(byteValue, &files)
	// Not all files are dumps, this struct will only contain zip dumps
	dumpFiles := Files{}
	for _, item := range files.File {
		if item.Format == "ZIP" {
			item.DumpType = strings.Split(item.Name, ".")[0]
			dumpFiles.File = append(dumpFiles.File, item)
		}
	}
	return dumpFiles
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}



func ByteCountSI(b int64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB",
		float64(b)/float64(div), "kMGTPE"[exp])
}

func Unzip(src string, dest string) ([]string, error) {
	var filenames []string
	r, err := zip.OpenReader(src)
	if err != nil {
		return filenames, err
	}
	defer r.Close()
	for _, f := range r.File {
		fpath := filepath.Join(dest, f.Name)
		if !strings.HasPrefix(fpath, filepath.Clean(dest)+string(os.PathSeparator)) {
			return filenames, fmt.Errorf("%s: illegal file path", fpath)
		}

		filenames = append(filenames, fpath)
		if f.FileInfo().IsDir() {
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}
		if err = os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return filenames, err
		}
		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return filenames, err
		}
		rc, err := f.Open()
		if err != nil {
			return filenames, err
		}
		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
		if err != nil {
			return filenames, err
		}
	}
	return filenames, nil
}
