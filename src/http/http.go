package httpproxy

import (
	auth "../interface/push"
	"fmt"
	"net/http"
	"sync"

	"github.com/tabalt/gracehttp"
)

func ListenAndServer(wg *sync.WaitGroup) {
	defer wg.Done()
	impl := new(auth.AuthImpl)
	http.HandleFunc("/qm/auth/set", func(w http.ResponseWriter, r *http.Request) {
		impl.AuthInfoSet(w, r)
	})
	http.HandleFunc("/qm/auth/get", func(w http.ResponseWriter, r *http.Request) {
		impl.AuthInfoGet(w, r)
	})
	http.HandleFunc("/qm/qrcode", func(w http.ResponseWriter, r *http.Request) {
		impl.GetQrcodeString(w, r)
	})

	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/", http.StripPrefix("/", fs))

	err := gracehttp.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Println(err)
	}
}
