// Package h2fp computes an Akamai-style HTTP/2 client fingerprint (design
// section 3.2): SETTINGS in order, the connection WINDOW_UPDATE increment,
// PRIORITY frames, and the pseudo-header order of the first HEADERS frame.
//
// It works by teeing the first bytes read from the decrypted TLS
// connection. http.Server's TLSNextProto hook hands the *tls.Conn to
// http2.Server.ServeConn through a recording wrapper, so the HTTP/2 server
// itself is unchanged.
package h2fp

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// Print is a parsed fingerprint.
type Print struct {
	Settings     []string // "id:value" in order
	WindowUpdate uint32
	Priority     int    // number of PRIORITY frames before the first HEADERS
	Pseudo       string // e.g. "m,a,s,p"
}

// String is the Akamai text form: settings|window|priority|pseudo.
func (p *Print) String() string {
	return fmt.Sprintf("%s|%d|%d|%s", strings.Join(p.Settings, ";"), p.WindowUpdate, p.Priority, p.Pseudo)
}

// Parse reads the client preface and frames up to the first HEADERS.
func Parse(b []byte) (*Print, bool) {
	if !bytes.HasPrefix(b, []byte(preface)) {
		return nil, false
	}
	fr := http2.NewFramer(nil, bytes.NewReader(b[len(preface):]))
	fr.ReadMetaHeaders = nil
	p := &Print{}
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			return nil, false // incomplete; caller waits for more bytes
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				_ = f.ForeachSetting(func(s http2.Setting) error {
					p.Settings = append(p.Settings, fmt.Sprintf("%d:%d", s.ID, s.Val))
					return nil
				})
			}
		case *http2.WindowUpdateFrame:
			if f.StreamID == 0 && p.WindowUpdate == 0 {
				p.WindowUpdate = f.Increment
			}
		case *http2.PriorityFrame:
			p.Priority++
		case *http2.HeadersFrame:
			var order []string
			dec := hpack.NewDecoder(65536, func(hf hpack.HeaderField) {
				if strings.HasPrefix(hf.Name, ":") && len(hf.Name) > 1 {
					order = append(order, hf.Name[1:2])
				}
			})
			if _, err := dec.Write(f.HeaderBlockFragment()); err != nil {
				return nil, false
			}
			p.Pseudo = strings.Join(order, ",")
			return p, true
		}
	}
}

// Classify maps a fingerprint to a client family. Values measured from real
// clients on 2026-10-22 with testing/tlsclients/measure:
//
//	Chromium 156  1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
//	Firefox 157   1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s
//	curl 8.18     3:100;4:65536;2:0|1048510465|0|m,s,a,p
//	Go 1.26       2:0;4:4194304;5:1048576;6:10485760|1073741824|0|a,m,p,s
//
// Safari is from published captures (m,s,p,a with setting 9) and is not yet
// measured here. Unknown prints are "other", which never fires a rule.
func Classify(p *Print) string {
	if p == nil {
		return "none"
	}
	return ClassifyText(p.String())
}

// ClassifyText classifies the Akamai text form (also used for the
// Doorkeep-H2 header forwarded by trusted proxies).
func ClassifyText(t string) string {
	parts := strings.Split(t, "|")
	if len(parts) != 4 {
		return "none"
	}
	set, pseudo := ";"+parts[0]+";", parts[3]
	switch pseudo {
	case "m,a,s,p":
		if strings.Contains(set, ";4:6291456;") {
			return "chrome"
		}
	case "m,p,a,s":
		if strings.Contains(set, ";4:131072;") {
			return "firefox"
		}
	case "m,s,p,a":
		return "safari"
	case "m,s,a,p":
		if strings.Contains(set, ";9:1;") {
			return "safari"
		}
		if strings.Contains(set, ";3:100;") {
			return "curl"
		}
	case "a,m,p,s":
		return "go"
	}
	return "other"
}

// Conn tees reads until a fingerprint is parsed. It delegates
// ConnectionState so http2.Server still sees TLS.
type Conn struct {
	*tls.Conn
	mu    sync.Mutex
	buf   []byte
	done  bool
	print *Print
}

const maxTee = 64 << 10

func (c *Conn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		if !c.done {
			c.buf = append(c.buf, p[:n]...)
			if pr, ok := Parse(c.buf); ok {
				c.print, c.done, c.buf = pr, true, nil
			} else if len(c.buf) > maxTee {
				c.done, c.buf = true, nil
			}
		}
		c.mu.Unlock()
	}
	return n, err
}

// Print returns the fingerprint once the first HEADERS frame was read.
func (c *Conn) Print() *Print {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.print
}

// NetConn exposes the TLS conn's underlying connection.
func (c *Conn) NetConn() net.Conn { return c.Conn.NetConn() }
