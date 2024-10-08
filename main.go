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
	)

	if optTitle == "" {
		optTitle = "Protected by QuickAuth"
	}
	if optListen == "" {
		optListen = ":80"
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

	s := rg.Must(newServer(serverOptions{
		htmlAuthorize:  htmlAuthorize.Bytes(),
		htmlFailed:     htmlFailed.Bytes(),
		listen:         optListen,
		target:         optTarget,
		targetInsecure: optTargetInsecure,
		secretKey:      optSecretKey,
		username:       optUsername,
		password:       optPassword,
	}))

	chErr := make(chan error, 1)
	chSig := make(chan os.Signal, 1)
	signal.Notify(chSig, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		chErr <- s.ListenAndServe()
	}()

	select {
	case err = <-chErr:
		return
	case sig := <-chSig:
		log.Println("signal caught:", sig.String())
	}

	err = s.Shutdown(context.Background())
}
