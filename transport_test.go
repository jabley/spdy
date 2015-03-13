package spdy

import (
	"net/http"
	"os"
	"testing"
)

func TestTransportExternal(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://www.performance.service.gov.uk/data/transactional-services/summaries?sort_by=_timestamp:descending&filter_by=service_id:dh-blood-donation-appointments&filter_by=type:seasonally-adjusted", nil)
	// req, _ := http.NewRequest("GET", "https://127.0.0.1:10443/", nil)
	rt := &Transport{
		InsecureTLSDial: true,
	}
	res, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("%v", err)
	}
	res.Write(os.Stdout)
}
