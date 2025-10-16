package main

import (
	"fmt"
	"github.com/termermc/go-capjs/cap"
	"github.com/termermc/go-capjs/cap/server"
	"log/slog"
	"net/http"
)

type HttpServer struct {
	logger *slog.Logger
	cap    *cap.Cap
	db     *DB
	env    *Env
	ipFunc server.IPExtractorFunc
}

func NewHttpServer(
	logger *slog.Logger,
	cap *cap.Cap,
	db *DB,
	env *Env,
	ipFunc server.IPExtractorFunc,
) *HttpServer {
	return &HttpServer{
		logger: logger,
		cap:    cap,
		db:     db,
		env:    env,
		ipFunc: ipFunc,
	}
}

type handlerWrapper struct {
	s *HttpServer
}

func (h *handlerWrapper) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	h.s.handler(res, req)
}

func (s *HttpServer) handler(res http.ResponseWriter, req *http.Request) {
	_, _ = res.Write([]byte("hello world"))
}

func (s *HttpServer) Listen() error {
	return http.ListenAndServe(fmt.Sprintf("%s:%d", s.env.ServerHostname, s.env.ServerPort), &handlerWrapper{s})
}
