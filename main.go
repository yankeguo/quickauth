package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"errors"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"text/template"
	"time"

	"github.com/yankeguo/rg"
)

//go:embed template/*
var res embed.FS

func main() {
	var err error
	defer func() {
		if err == nil {
			return
		}
		log.Println("exited with error:", err.Error())
		os.Exit(1)
	}()
	defer rg.Guard(&err)

	var (
		optTitle             = os.Getenv("QUICKAUTH_TITLE")
		optListen            = os.Getenv("QUICKAUTH_LISTEN")
		optTarget            = os.Getenv("QUICKAUTH_TARGET")
		optTargetInsecure, _ = strconv.ParseBool(os.Getenv("QUICKAUTH_TARGET_INSECURE"))
		optSecretKey         = os.Getenv("QUICKAUTH_SECRET_KEY")
		optUsername          = os.Getenv("QUICKAUTH_USERNAME")
		optPassword          = os.Getenv("QUICKAUTH_PASSWORD")
		optTLSCert           = os.Getenv("QUICKAUTH_TLS_CERT")
		optTLSKey            = os.Getenv("QUICKAUTH_TLS_KEY")
	)

	if optTitle == "" {
		optTitle = "Protected by QuickAuth"
	}
	if optListen == "" {
		if optTLSCert != "" && optTLSKey != "" {
			optListen = ":443"
		} else {
			optListen = ":80"
		}
	}
	if optTarget == "" {
		err = errors.New("QUICKAUTH_TARGET is required")
		return
	}
	if optSecretKey == "" {
		buf := make([]byte, 16)
		rg.Must(rand.Read(buf))
		optSecretKey = hex.EncodeToString(buf)
	}
	if optUsername == "" {
		err = errors.New("QUICKAUTH_USERNAME is required")
		return
	}
	if optPassword == "" {
		err = errors.New("QUICKAUTH_PASSWORD is required")
		return
	}

	web := rg.Must(template.ParseFS(res, "template/*.html"))

	htmlAuthorize := &bytes.Buffer{}

	rg.Must0(
		web.ExecuteTemplate(
			htmlAuthorize,
			"authorize.html",
			map[string]string{
				"Title": optTitle,
			},
		),
	)

	htmlFailed := &bytes.Buffer{}

	rg.Must0(
		web.ExecuteTemplate(
			htmlFailed,
			"failed.html",
			map[string]string{
				"Title": optTitle,
			},
		),
	)

	tlsEnabled := optTLSCert != "" && optTLSKey != ""

	s := rg.Must(newServer(serverOptions{
		htmlAuthorize:  htmlAuthorize.Bytes(),
		htmlFailed:     htmlFailed.Bytes(),
		listen:         optListen,
		target:         optTarget,
		targetInsecure: optTargetInsecure,
		secretKey:      optSecretKey,
		username:       optUsername,
		password:       optPassword,
		secureCookie:   tlsEnabled,
	}))

	chErr := make(chan error, 1)
	chSig := make(chan os.Signal, 1)
	signal.Notify(chSig, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		if tlsEnabled {
			chErr <- s.ListenAndServeTLS(optTLSCert, optTLSKey)
		} else {
			chErr <- s.ListenAndServe()
		}
	}()

	select {
	case err = <-chErr:
		return
	case sig := <-chSig:
		log.Println("signal caught:", sig.String())
	}

	// Bound the graceful shutdown: http.Server.Shutdown waits for all active
	// connections, and long-lived streams (SSE, WebSocket) may never finish on
	// their own. Fall back to a forceful close once the grace period expires.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err = s.Shutdown(ctx); err != nil {
		log.Println("graceful shutdown timed out, closing forcefully:", err.Error())
		err = s.Close()
	}
}
