package writeresult

import (
    "math/rand"
    "bytes"
	"os"
	"fmt"
	"time"
)

func Writeresult(writelist []string)  {
	char := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    rand.NewSource(time.Now().UnixNano()) // 产生随机种子
    var s bytes.Buffer
    for i := 0; i < 6; i ++ {
        s.WriteByte(char[rand.Int63() % int64(len(char))])
    }
    
    file, err := os.OpenFile("result_"+s.String()+".txt", os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0666)
    if err != nil {
       fmt.Printf("%v", err)
    }
    defer file.Close()

    for _, value := range writelist {
		if value == ""{
			continue
		}
        file.WriteString(value + "\n")
    }
}



func Domainin(target string, str_array []string) bool { 

	for _, element := range str_array{ 

	   if target == element{ 

		   return true 

	   } 

   } 

   return false 

} 