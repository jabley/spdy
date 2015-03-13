package spdy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
)

type Transport struct {
	connMu          sync.Mutex
	conns           map[string][]*clientConn
	InsecureTLSDial bool
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	host, port, err := net.SplitHostPort(req.URL.Host)
	if err != nil {
		host = req.URL.Host
		port = "443"
	}

	for {
		cc, err := t.getClientConn(host, port)
		if err != nil {
			return nil, err
		}
		res, err := cc.roundTrip(req)
		if shouldRetryRequest(err) { // TODO: or clientconn is overloaded (too many outstanding requests)?
			continue
		}
		if err != nil {
			return nil, err
		}
		return res, nil
	}

}

type clientConn struct {
	t        *Transport
	tconn    *tls.Conn
	tlsState *tls.ConnectionState
	connKey  []string // key(s) this connection is cached in, in t.conns

	readerDone chan struct{} // closed on error
	readerErr  error         // set before readerDone is closed
	dec        *decoder
	nextRes    *http.Response

	mu           sync.Mutex
	closed       bool
	goAway       *GoAwayFrame
	streams      map[uint32]*clientStream
	nextStreamID uint32
	bw           *bufio.Writer
	werr         error // first write error that has occurred
	br           *bufio.Reader
	fr           *Framer

	// Settings from peer:
	maxFrameSize         uint32
	maxConcurrentStreams uint32
	initialWindowSize    uint32
	hbuf                 bytes.Buffer // HPACK encoder writes into this
	enc                  *encoder
}

type clientStream struct {
	ID   uint32
	resc chan resAndError
	pw   *io.PipeWriter
	pr   *io.PipeReader
	buf  *bytes.Buffer
	req  *http.Request
}

type stickyErrWriter struct {
	w   io.Writer
	err *error
}

type resAndError struct {
	res *http.Response
	err error
}

func (sew stickyErrWriter) Write(p []byte) (n int, err error) {
	if *sew.err != nil {
		return 0, *sew.err
	}
	n, err = sew.w.Write(p)
	*sew.err = err
	return
}

func filterOutClientConn(in []*clientConn, exclude *clientConn) []*clientConn {
	out := in[:0]
	for _, v := range in {
		if v != exclude {
			out = append(out, v)
		}
	}
	return out
}

func (t *Transport) getClientConn(host, port string) (*clientConn, error) {
	t.connMu.Lock()
	defer t.connMu.Unlock()

	key := net.JoinHostPort(host, port)

	for _, cc := range t.conns[key] {
		if cc.canTakeNewRequest() {
			return cc, nil
		}
	}
	if t.conns == nil {
		t.conns = make(map[string][]*clientConn)
	}
	cc, err := t.newClientConn(host, port, key)
	if err != nil {
		return nil, err
	}
	t.conns[key] = append(t.conns[key], cc)
	return cc, nil
}

func (t *Transport) newClientConn(host, port, key string) (*clientConn, error) {
	// log.Printf("Creating a new client connection for %s\n", key)

	cfg := &tls.Config{
		ServerName:         host,
		NextProtos:         []string{NextProtoTLS},
		InsecureSkipVerify: t.InsecureTLSDial,
	}
	tconn, err := tls.Dial("tcp", host+":"+port, cfg)
	if err != nil {
		return nil, err
	}
	if err := tconn.Handshake(); err != nil {
		tconn.Close()
		return nil, err
	}
	if !t.InsecureTLSDial {
		if err := tconn.VerifyHostname(cfg.ServerName); err != nil {
			tconn.Close()
			return nil, err
		}
	}
	state := tconn.ConnectionState()
	if p := state.NegotiatedProtocol; p != NextProtoTLS {
		// TODO(jabley): fall back to Fallback
		tconn.Close()
		return nil, fmt.Errorf("bad protocol: %v", p)
	}
	if !state.NegotiatedProtocolIsMutual {
		tconn.Close()
		return nil, fmt.Errorf("could not negotiate protocol mutually %q", state.NegotiatedProtocol)
	}

	// log.Printf("Got a client connection\n")

	cc := &clientConn{
		t:                    t,
		tconn:                tconn,
		connKey:              []string{key}, // TODO: cert's validated hostnames too
		tlsState:             &state,
		readerDone:           make(chan struct{}),
		nextStreamID:         1,
		maxFrameSize:         16 << 10, // spec default
		initialWindowSize:    65535,    // spec default
		maxConcurrentStreams: 1000,     // "infinite", per spec. 1000 seems good enough.
		streams:              make(map[uint32]*clientStream),
	}
	cc.bw = bufio.NewWriter(stickyErrWriter{tconn, &cc.werr})
	cc.br = bufio.NewReader(tconn)
	cc.fr = NewFramer(cc.bw, cc.br)
	cc.enc = NewEncoder()

	cc.fr.WriteSettings(Setting{SettingMaxConcurrentStreams, 0, cc.maxConcurrentStreams})

	// log.Printf("Wrote settings to server\n")

	cc.bw.Flush()
	if cc.werr != nil {
		tconn.Close()
		return nil, cc.werr
	}

	cc.dec = NewDecoder()

	go cc.readLoop()
	return cc, nil
}

func (t *Transport) removeClientConn(cc *clientConn) {
	t.connMu.Lock()
	defer t.connMu.Unlock()
	for _, key := range cc.connKey {
		vv, ok := t.conns[key]
		if !ok {
			continue
		}
		newList := filterOutClientConn(vv, cc)
		if len(newList) > 0 {
			t.conns[key] = newList
		} else {
			delete(t.conns, key)
		}
	}
}

func (cc *clientConn) roundTrip(req *http.Request) (*http.Response, error) {
	cc.mu.Lock()

	if cc.closed {
		cc.mu.Unlock()
		return nil, errClientConnClosed
	}

	cs := cc.newStream(req)
	// TODO(jabley): Only need to support GET at the moment, which doesn't have a body
	hasBody := false

	// we send: SYN_STREAM + (DATA?)
	hdrs, err := cc.encodeHeaders(req)

	if err != nil {
		return nil, err
	}

	// (jabley) – no DATA since we are only implementing GET and HEAD
	syn := SynStreamFrame{StreamID: cs.ID, Headers: hdrs}
	syn.Flags = FlagFin // No DataFrame for now
	cc.fr.WriteSynStream(syn)

	cc.bw.Flush()
	werr := cc.werr
	cc.mu.Unlock()

	if hasBody {
		// TODO: write data. and it should probably be interleaved:
		//   go ... io.Copy(dataFrameWriter{cc, cs, ...}, req.Body) ... etc
	}

	// log.Printf("Sent request with error %q\n", werr)

	if werr != nil {
		return nil, werr
	}

	re := <-cs.resc
	if re.err != nil {
		return nil, re.err
	}
	res := re.res
	res.Request = req
	res.TLS = cc.tlsState
	return res, nil
}

// requires cc.mu be held.
func (cc *clientConn) encodeHeaders(req *http.Request) ([]byte, error) {
	cc.hbuf.Reset()

	url := req.URL

	path := url.Path
	if url.RawQuery != "" {
		path += "?" + url.RawQuery
	}
	if url.Fragment != "" {
		path += "#" + url.Fragment
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	host := url.Host
	if req.Host != "" {
		host = req.Host
	}

	header := req.Header
	header.Set("method", req.Method)
	header.Set("url", path)
	header.Set("version", "HTTP/1.1")
	header.Set("host", host)
	header.Set("scheme", url.Scheme)

	return cc.enc.Encode(header)
}

func (cc *clientConn) setGoAway(f *GoAwayFrame) {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	cc.goAway = f
}

func (cc *clientConn) canTakeNewRequest() bool {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.goAway == nil &&
		int64(len(cc.streams)+1) < int64(cc.maxConcurrentStreams) &&
		cc.nextStreamID < 2147483647
}

// requires cc.mu be held.
func (cc *clientConn) newStream(req *http.Request) *clientStream {
	cs := &clientStream{
		ID:   cc.nextStreamID,
		resc: make(chan resAndError, 1),
		req:  req,
	}
	cc.nextStreamID += 2
	cc.streams[cs.ID] = cs
	return cs
}

func (cc *clientConn) streamByID(id uint32, andRemove bool) *clientStream {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	cs := cc.streams[id]
	if andRemove {
		delete(cc.streams, id)
	}
	return cs
}

// runs in its own goroutine.
func (cc *clientConn) readLoop() {
	defer cc.t.removeClientConn(cc)
	defer close(cc.readerDone)

	activeRes := map[uint32]*clientStream{} // keyed by streamID
	// Close any response bodies if the server closes prematurely.
	// TODO: also do this if we've written the headers but not
	// gotten a response yet.
	defer func() {
		err := cc.readerErr
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		for _, cs := range activeRes {
			cs.pw.CloseWithError(err)
		}
	}()

	// continueStreamID is the stream ID we're waiting for
	// continuation frames for.
	// var continueStreamID uint32

	for {
		// log.Printf("Entered read loop for %v\n", cc.connKey)
		f, err := cc.fr.ReadFrame()
		if err != nil {
			// log.Printf("Error reading the frame %v\n", err)
			cc.readerErr = err
			return
		}

		// log.Printf("Transport received %#v", f)

		var streamID uint32

		streamEnded := false
		if ff, ok := f.(streamEnder); ok {
			// log.Printf("Checking Stream has ended\n")
			streamEnded = ff.StreamEnded()
		}

		// log.Printf("Stream Ended? %v for %v\n", streamEnded, f.Header())

		var cs *clientStream

		switch f := f.(type) {
		case *SettingsFrame:
			f.ForeachSetting(func(s Setting) error {
				switch s.ID {
				case SettingMaxConcurrentStreams:
					cc.maxConcurrentStreams = s.Val
				default:
					// TODO(jabley): handle more
					log.Printf("Unhandled Setting: %v", s)
				}
				return nil
			})
		case *SynReplyFrame:
			if f.StreamID%2 == 0 {
				// Ignore server push for now
				break
			}

			cs = cc.streamByID(f.StreamID, streamEnded)
			cc.nextRes = &http.Response{
				Proto:      "HTTP/1.1",
				ProtoMajor: 1,
			}
			// cs.pr, cs.pw = io.Pipe()
			cs.buf = &bytes.Buffer{}
			header, err := cc.dec.Decode(f.Headers)

			if err != nil {
				// log.Printf("Error reading %v: %v\n", f, err)
				cc.readerErr = err
			}
			cc.nextRes.Header = header

			log.Printf("Read headers %v\n", header)
		case *DataFrame:
			cs = cc.streamByID(f.StreamID, streamEnded)
			// log.Printf("DATA: %q", f.Data())
			// log.Printf("Writing data to pipe\n")
			// _, err := cs.pw.Write(f.Data())
			cs.buf.Write(f.Data())
			// log.Printf("Wrote data to pipe\n")
		// case *GoAwayFrame:
		// 	cc.t.removeClientConn(cc)
		// 	if f.ErrCode != 0 {
		// 		// TODO: deal with GOAWAY more. particularly the error code
		// 		log.Printf("transport got GOAWAY with error code = %v", f.ErrCode)
		// 	}
		// 	cc.setGoAway(f)
		default:
			log.Printf("Transport: unhandled response frame type %T", f)
		}

		if streamEnded {
			// cs.pw.Close()
			delete(activeRes, streamID)
			body := &ClosingBuffer{cs.buf}

			if unrequestedGzip(cs.req.Header, cc.nextRes.Header) {
				cc.nextRes.Body = &gzipReader{body: body}
			} else {
				cc.nextRes.Body = body
			}

			res := cc.nextRes
			cs.resc <- resAndError{res: res}
		}
	}
}

var errClientConnClosed = errors.New("spdy: client conn is closed")

func shouldRetryRequest(err error) bool {
	return false
}

func notImplemented() error {
	return fmt.Errorf("Not implemented")
}

type ClosingBuffer struct {
	*bytes.Buffer
}

func (cb *ClosingBuffer) Close() error {
	return nil
}

// unrequestedGzip returns true if the request did
// not ask for the returned content encoding and that
// encoding is gzip, which is allowed in the SPDY spec.
func unrequestedGzip(reqHeader http.Header, resHeader http.Header) bool {
	got := resHeader.Get("Content-Encoding")
	switch got {
	case "gzip":
	default:
		return false
	}

	requested := reqHeader.Get("Accept-Encoding")
	return !strings.Contains(requested, got)
}

// gzipReader wraps a response body so it can lazily
// call gzip.NewReader on the first call to Read
type gzipReader struct {
	body io.ReadCloser // underlying Response.Body
	zr   io.Reader     // lazily-initialized gzip reader
}

func (gz *gzipReader) Read(p []byte) (n int, err error) {
	if gz.zr == nil {
		gz.zr, err = gzip.NewReader(gz.body)
		if err != nil {
			return 0, err
		}
	}
	return gz.zr.Read(p)
}

func (gz *gzipReader) Close() error {
	return gz.body.Close()
}
