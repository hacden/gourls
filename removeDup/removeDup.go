package removeDup

import "sort"

//这种发放适用于string,int,float等切片，会对切片中的元素进行排序
func RemoveDup(slice []string) []string {
    sort.Strings(slice)
    i:= 0
    var j int
    for{
      if i >= len(slice)-1 {
       break
      }
   
      for j = i + 1; j < len(slice) && slice[i] == slice[j]; j++ {
      }
      slice= append(slice[:i+1], slice[j:]...)
      i++
    }
    return slice
}
  