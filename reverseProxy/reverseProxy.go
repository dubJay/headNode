package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

        "github.com/gorilla/handlers"
)

var (	
	cert        = flag.String("cert", "", "Concatenation of server's certificate and any intermediates.")
	hosts       = flag.String("hosts", "", "CSV of all hosts to load balance across")
	key         = flag.String("key", "", "Private key for TLS")
	logDir      = flag.String("logDir", "logs", "Name of logging dir. Will be joined with rootDir")
	port        = flag.String("port", ":8080", "Port for server to listen on")
	rootDir     = flag.String("rootDir", "", "Path to webdir structure")
	ssl         = flag.Bool("ssl", false, "Whether to use TLS")

	// Optional secondary TLS info.
	secondCert        = flag.String("secondCert", "", "Concatenation of server's certificate and any intermediates.")
	secondKey         = flag.String("secondKey", "", "Private key for TLS")
)

// Simple round robin queue. ATM all backend comps have equal compute power.
func populateQueue(hosts []string) ([]*url.URL, error) {
	var queue []*url.URL
	if len(hosts) == 0 {
		return queue, errors.New("No hosts provided for reverse proxy")
	}

	// Populate queue.
	for _, host := range hosts {
		// TODO: Validate host can be reached.
		url, err := url.Parse(host)
		if err != nil {
			return queue, fmt.Errorf("Error parsing url %s: %v", host, err)
		}
		queue = append(queue, url)
	}

	return queue, nil
}

func getNext(hosts []*url.URL, i *int) *url.URL {
	if len(hosts) == 0 {
		return &url.URL{}
	}

	if *i >= len(hosts) { *i = 0 }
	url := hosts[*i]
	*i++

	return url
}

// Copy from https://golang.org/src/net/http/httputil/reverseproxy.go
func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

// Two subdomains point to this IP. As such we need to determine where they need to be directed.
func interceptPath(url *url.URL, host string) string {
	// URL host is often empty.
	if strings.Contains(host, "unofficialscp") {
		return filepath.Join("scp", url.Path)
	}
	if strings.Contains(host, "kathryn") {
		return filepath.Join("kcawd", url.Path)
	}
	return url.Path
}

func newMultiHostReverseProxy(hosts []*url.URL) *httputil.ReverseProxy {
	// Remnant of SingleHostReverseProxy.
	targetQuery := ""
	i := 0
	director := func(req *http.Request) {
		var target = getNext(hosts, &i)
		path := interceptPath(req.URL, req.Host)
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = singleJoiningSlash(target.Path, path)
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
		if _, ok := req.Header["User-Agent"]; !ok {
			// explicitly disable User-Agent so it's not set to default value
			req.Header.Set("User-Agent", "")
		}
	}
	return &httputil.ReverseProxy{Director: director}
}

func redirect(w http.ResponseWriter, req *http.Request) {
	// remove/add not default ports from req.Host
	target := "https://" + req.Host + *port + req.URL.Path
	if len(req.URL.RawQuery) > 0 {
		target += "?" + req.URL.RawQuery
	}
	http.Redirect(w, req, target, http.StatusTemporaryRedirect)
}

func setupLogging() (*os.File, error) {
	if *logDir == "" {
		return nil, errors.New("logDir flag must be set")
	}

	now := time.Now().UTC()
	nowString := fmt.Sprintf("%d-%02d-%02d", now.Year(), now.Month(), now.Day())
	logFile := filepath.Join(*rootDir, *logDir, fmt.Sprintf("access-logs_%s.txt", nowString))

	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		return os.Create(logFile)
	}
	return os.Open(logFile)
}


func main() {
	flag.Parse()

	queue, err := populateQueue(strings.Split(*hosts, ","))
	if err != nil {
		log.Fatal(err)
	}

	file, err := setupLogging()
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", newMultiHostReverseProxy(queue).ServeHTTP)
	
	if !*ssl {
		log.Fatal(http.ListenAndServe(*port, mux))
	} else {
		go http.ListenAndServe(":80", http.HandlerFunc(redirect))

		handler := handlers.CombinedLoggingHandler(file, mux)
		if len(*secondCert) == 0 || len(*secondKey) == 0 {
			log.Fatal(http.ListenAndServeTLS(*port, *cert, *key, handler))
		}

		tlsConfig := &tls.Config{}
		tlsConfig.Certificates = make([]tls.Certificate, 2)
		tlsConfig.Certificates[0], err = tls.LoadX509KeyPair(*cert, *key)
		if err != nil {
			log.Fatal(err)
		}
		tlsConfig.Certificates[1], err = tls.LoadX509KeyPair(*secondCert, *secondKey)
		if err != nil {
			log.Fatal(err)
		}
		tlsConfig.BuildNameToCertificate()

		server := &http.Server{
			Handler: handler,
			ReadTimeout:    2 * time.Second,
			WriteTimeout:   30 * time.Second,
			TLSConfig: tlsConfig,
		}
		server.ListenAndServeTLS("", "")
	}
}
