package spdy

import (
	"net/http"
	"os"
	"testing"
)

func TestTransportExternal(t *testing.T) {
	// req, _ := http.NewRequest("GET", "https://www.performance.service.gov.uk/", nil)
	req, _ := http.NewRequest("GET", "https://127.0.0.1:10443/", nil)
	rt := &Transport{
		InsecureTLSDial: true,
	}
	res, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("%v", err)
	}
	res.Write(os.Stdout)
}
