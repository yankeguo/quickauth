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
		optTitle             = os.Getenv("AUTHRP_TITLE")
		optListen            = os.Getenv("AUTHRP_LISTEN")
		optTarget            = os.Getenv("AUTHRP_TARGET")
		optTargetInsecure, _ = strconv.ParseBool(os.Getenv("AUTHRP_TARGET_INSECURE"))
		optSecretKey         = os.Getenv("AUTHRP_SECRET_KEY")
		optUsername          = os.Getenv("AUTHRP_USERNAME")
		optPassword          = os.Getenv("AUTHRP_PASSWORD")
	)

	if optTitle == "" {
		optTitle = "Protected by AuthRP"
	}
	if optListen == "" {
		optListen = ":80"
	}
	if optTarget == "" {
		err = errors.New("AUTHRP_TARGET is required")
		return
	}
	if optSecretKey == "" {
		buf := make([]byte, 16)
		rg.Must(rand.Read(buf))
		optSecretKey = hex.EncodeToString(buf)
	}
	if optUsername == "" {
		err = errors.New("AUTHRP_USERNAME is required")
		return
	}
	if optPassword == "" {
		err = errors.New("AUTHRP_PASSWORD is required")
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
