package main

import (
	"./http"
	"fmt"
	"sync"
)

func main() {
	wg := &sync.WaitGroup{}
	fmt.Printf("Auth server\n")

	wg.Add(1)
	httpproxy.ListenAndServer(wg)
	fmt.Printf("Auth server over\n")
	wg.Wait()

}
