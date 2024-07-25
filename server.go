package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/yankeguo/rg"
)

const (
	PathMetrics   = "/__authrp/metrics"
	PathReady     = "/__authrp/ready"
	PathAuthorize = "/__authrp/authorize"
	PathFailed    = "/__authrp/failed"
)

var (
	metricLabels = []string{"request_method", "request_path", "authenticated"}

	metricRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "authrp_proxy_http_requests_total",
		Help: "The total number of handled http request",
	}, metricLabels)

	metricRequestsDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "authrp_proxy_http_requests_duration",
		Help: "The duration of handled http request",
	}, metricLabels)
)

type serverOptions struct {
	htmlAuthorize  []byte
	htmlFailed     []byte
	listen         string
	target         string
	targetInsecure bool
	secretKey      string
	username       string
	password       string
}

func newServer(opts serverOptions) (s *http.Server, err error) {
	defer rg.Guard(&err)

	hR := httputil.NewSingleHostReverseProxy(rg.Must(url.Parse(opts.target)))
	hR.Transport = &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		DialContext:       (&net.Dialer{}).DialContext,
		ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: opts.targetInsecure,
		},
	}

	hP := promhttp.Handler()

	s = &http.Server{
		Addr: opts.listen,
		Handler: http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			// metrics
			if req.URL.Path == PathMetrics {
				hP.ServeHTTP(rw, req)
				return
			}

			// ready
			if req.URL.Path == PathReady {
				http.Error(rw, "OK", http.StatusOK)
				return
			}

			// authorize
			if req.URL.Path == PathAuthorize {
				if req.Method == http.MethodPost {
					var (
						username = req.FormValue("username")
						password = req.FormValue("password")
					)
					if (username == opts.username) && (password == opts.password) {
						setAuthCookie(rw, opts.secretKey, username)
						redirect := req.URL.Query().Get("redirect")
						if redirect == "" {
							redirect = "/"
						}
						http.Redirect(rw, req, redirect, http.StatusFound)
						return
					} else {
						http.Redirect(rw, req, PathFailed, http.StatusFound)
						return
					}
				} else {
					rw.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
					rw.Header().Set("Content-Type", "text/html; charset=utf-8")
					rw.Header().Set("Content-Length", strconv.Itoa(len(opts.htmlAuthorize)))
					rw.Write(opts.htmlAuthorize)
					return
				}
			}

			// failed
			if req.URL.Path == PathFailed {
				rw.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
				rw.Header().Set("Content-Type", "text/html; charset=utf-8")
				rw.Header().Set("Content-Length", strconv.Itoa(len(opts.htmlFailed)))
				rw.WriteHeader(http.StatusUnauthorized)
				rw.Write(opts.htmlFailed)
				return
			}

			var (
				startedAt     = time.Now()
				authenticated = checkAuthCookie(req, opts.secretKey, opts.username)
			)

			if authenticated {
				hR.ServeHTTP(rw, req)
			} else {
				http.Redirect(rw, req, PathAuthorize+"?redirect="+url.QueryEscape(req.RequestURI), http.StatusFound)
			}

			// metrics
			metricFields := prometheus.Labels{
				"request_method": req.Method,
				"request_path":   req.URL.Path,
				"authenticated":  strconv.FormatBool(authenticated),
			}
			metricRequestsTotal.With(metricFields).Inc()
			metricRequestsDuration.With(metricFields).Observe(float64(time.Since(startedAt)/time.Millisecond) / float64(time.Second/time.Millisecond))
		}),
	}
	return
}
