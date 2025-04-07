package runtime

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
)

var cgs_latency_ok = prometheus.NewHistogram(
    prometheus.HistogramOpts{
        Name:    "http_success_latency_ms",
        Help:    "Latency of successful HTTP requests in ms.",
        Buckets: []float64{10, 20, 40, 60, 80, 100, 150, 200, 300, 400, 500, 750, 1000, 1500, 2000, 2500, 3000},
    },
)
var cgs_latency_fail= prometheus.NewHistogram(
    prometheus.HistogramOpts{
        Name:    "http_failure_latency_ms",
        Help:    "Latency of failed HTTP requests in ms.",
        Buckets: []float64{10, 20, 40, 60, 80, 100, 150, 200, 300, 400, 500, 750, 1000, 1500, 2000, 2500, 3000},
    },
)

func cgs_stats_init() {
	go func() {
    	http.Handle("/metrics", promhttp.Handler())
    	http.ListenAndServe(":2112", nil)  // Or any unused port
	}()
	prometheus.MustRegister(cgs_latency_ok)
	prometheus.MustRegister(cgs_latency_fail)
}

func cgs_stats_report(latency int64, success bool) {
	if success {
		cgs_latency_ok.Observe(float64(latency))
	} else {
		cgs_latency_fail.Observe(float64(latency))
	}
}

