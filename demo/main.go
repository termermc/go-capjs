package main

import (
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"github.com/termermc/go-capjs/cap"
	"github.com/termermc/go-capjs/cap/server"
	"github.com/termermc/go-capjs/sqlitedriver"
	"net/http"
	"net/netip"
)

const page = `
<!DOCTYPE html>
<html>
<head>
	<title>go-capjs demo</title>
</head>
<body>
	<h1>go-capjs demo</h1>
	<form method="post">
		<p>%s</p>
		
		<cap-widget id="cap" data-cap-api-endpoint="/cap/"></cap-widget>
		
		<br/>
		
		<input type="submit" />		
	</form>

	<script src="https://cdn.jsdelivr.net/npm/@cap.js/widget"></script>
</body>
</html>
`

func main() {
	const path = "./cap.sqlite?_journal=WAL"

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		panic(err)
	}

	driver, err := sqlitedriver.NewDriver(db,
		sqlitedriver.WithRateLimit(),
	)
	if err != nil {
		panic(err)
	}

	capSvc := cap.NewCap(driver)

	capServer := server.NewServer(capSvc,
		server.WithIPForRateLimit(func(req *http.Request) *netip.Addr {
			ip, err := netip.ParseAddr(req.RemoteAddr)
			if err == nil {
				return &ip
			} else {
				return nil
			}
		}),
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(res http.ResponseWriter, req *http.Request) {
		sendPage := func(status int, msg string) {
			res.WriteHeader(status)
			_, _ = fmt.Fprintf(res, page, msg)
		}

		if req.Method == http.MethodPost {
			if err := req.ParseForm(); err != nil {
				sendPage(400, "malformed body")
				return
			}

			token := req.Form.Get("cap-token")

			if token == "" {
				sendPage(400, "missing cap token")
				return
			}

			wasValid, err := capSvc.UseRedeemToken(req.Context(), token)
			if err != nil {
				sendPage(500, "error: "+err.Error())
				return
			}

			if wasValid {
				sendPage(200, "cap token was valid! success!")
			} else {
				sendPage(403, "invalid cap token")
			}
		} else {
			sendPage(200, "")
		}
	})
	mux.HandleFunc("/cap/challenge", capServer.ChallengeHandler)
	mux.HandleFunc("/cap/redeem", capServer.RedeemHandler)

	const listenAddr = "0.0.0.0:8080"
	fmt.Printf("Listening on %s\n", listenAddr)
	err = http.ListenAndServe(listenAddr, mux)
	if err != nil {
		panic(err)
	}
}
