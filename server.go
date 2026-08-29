package main

import (
	"crypto/subtle"
	"crypto/tls"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/yankeguo/rg"
)

const (
	PathMetrics   = "/__quickauth/metrics"
	PathReady     = "/__quickauth/ready"
	PathAuthorize = "/__quickauth/authorize"
	PathFailed    = "/__quickauth/failed"
)

var (
	metricLabels = []string{"request_method", "request_path", "authenticated"}

	metricRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "quickauth_proxy_http_requests_total",
		Help: "The total number of handled http request",
	}, metricLabels)

	metricRequestsDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "quickauth_proxy_http_requests_duration",
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
	secureCookie   bool
}

func newServer(opts serverOptions) (s *http.Server, err error) {
	defer rg.Guard(&err)

	hR := httputil.NewSingleHostReverseProxy(rg.Must(url.Parse(opts.target)))
	// FlushInterval < 0 means flush immediately after each write, ensuring
	// timely delivery of streaming responses (SSE, WebSocket, etc.)
	hR.FlushInterval = -1 * time.Nanosecond
	// Clone the default transport to inherit sane timeouts (TLS handshake,
	// idle connection, expect-continue) without hand-rolling them.
	hT := http.DefaultTransport.(*http.Transport).Clone()
	hT.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: opts.targetInsecure,
	}
	// ResponseHeaderTimeout MUST stay zero: it bounds the wait for the
	// upstream response headers, and a non-zero value would abort slow or
	// long-lived streaming endpoints (e.g. an SSE endpoint that sends no
	// headers until the first event).
	hT.ResponseHeaderTimeout = 0
	hR.Transport = hT

	hP := promhttp.Handler()

	s = &http.Server{
		Addr: opts.listen,
		// ReadHeaderTimeout and IdleTimeout protect against slowloris and
		// dead keep-alive connections. Neither affects an in-flight response.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		// ReadTimeout and WriteTimeout MUST stay zero: they bound the whole
		// lifetime of a request/response and would kill long-lived streaming
		// connections such as SSE and WebSocket.
		ReadTimeout:  0,
		WriteTimeout: 0,
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
					// constant-time comparison to avoid leaking credential
					// length/prefix through timing
					credentialsOK := subtle.ConstantTimeCompare([]byte(username), []byte(opts.username)) == 1 &&
						subtle.ConstantTimeCompare([]byte(password), []byte(opts.password)) == 1
					if credentialsOK {
						setAuthCookie(rw, opts.secretKey, username, opts.secureCookie)
						redirect := req.URL.Query().Get("redirect")
						// only allow local paths, preventing open redirects
						// (e.g. ?redirect=https://evil.example or //evil.example)
						if !strings.HasPrefix(redirect, "/") || strings.HasPrefix(redirect, "//") {
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
				if req.Method == http.MethodGet {
					http.Redirect(rw, req, PathAuthorize+"?redirect="+url.QueryEscape(req.RequestURI), http.StatusFound)
				} else {
					http.Error(rw, "Unauthorized", http.StatusUnauthorized)
				}
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
