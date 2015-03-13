package spdy

import (
	"bytes"
	"compress/zlib"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
)

var versionError = errors.New("Version not supported.")

var zlibV2Writers chan *zlib.Writer

func init() {
	zlibV2Writers = make(chan *zlib.Writer, 5)
}

// decoder is used to decode name/value header blocks.
// Decompressors retain their state, so a single decompressor
// should be used for each direction of a particular connection.
type decoder struct {
	sync.Mutex
	in  *bytes.Buffer
	out io.ReadCloser
}

// NewDecoder is used to create a new decoder.
func NewDecoder() *decoder {
	out := new(decoder)
	return out
}

// decode uses zlib decompression to decompress the provided
// data, according to the SPDY specification of the given version.
func (d *decoder) Decode(data []byte) (headers http.Header, err error) {
	d.Lock()
	defer d.Unlock()

	// Make sure the buffer is ready.
	if d.in == nil {
		d.in = bytes.NewBuffer(data)
	} else {
		d.in.Reset()
		d.in.Write(data)
	}

	// Initialise the decompressor with the appropriate
	// dictionary, depending on SPDY version.
	if d.out == nil {
		d.out, err = zlib.NewReaderDict(d.in, HeaderDictionary)

		if err != nil {
			return nil, err
		}
	}

	var size = 2
	var bytesToInt = func(b []byte) int {
		return int(BytesToUint16(b))
	}

	// return nil, notImplemented()
	// Read in the number of name/value pairs.
	pairs, err := ReadExactly(d.out, size)
	if err != nil {
		return nil, err
	}
	numNameValuePairs := bytesToInt(pairs)

	headers = make(http.Header)
	bounds := MAX_FRAME_SIZE - 12 // Maximum frame size minus maximum non-headers data (SYN_STREAM)
	for i := 0; i < numNameValuePairs; i++ {
		var nameLength, valueLength int

		// Get the name's length.
		length, err := ReadExactly(d.out, size)
		if err != nil {
			return nil, err
		}
		nameLength = bytesToInt(length)
		bounds -= size

		if nameLength > bounds {
			log.Printf("Error: Maximum header length is %d. Received name length %d.\n", bounds, nameLength)
			return nil, errors.New("Error: Incorrect header name length.")
		}
		bounds -= nameLength

		// Get the name.
		name, err := ReadExactly(d.out, nameLength)
		if err != nil {
			return nil, err
		}

		// Get the value's length.
		length, err = ReadExactly(d.out, size)
		if err != nil {
			return nil, err
		}
		valueLength = bytesToInt(length)
		bounds -= size

		if valueLength > bounds {
			log.Printf("Error: Maximum header length is %d. Received values length %d.\n", bounds, valueLength)
			return nil, errors.New("Error: Incorrect header values length.")
		}
		bounds -= valueLength

		// Get the values.
		values, err := ReadExactly(d.out, valueLength)
		if err != nil {
			return nil, err
		}

		// Split the value on null boundaries.
		for _, value := range bytes.Split(values, []byte{'\x00'}) {
			headers.Add(string(name), string(value))
		}
	}

	return headers, nil
}

// encoder is used to compress name/value header blocks.
// Encoders retain their state, so a single encoder
// should be used for each direction of a particular
// connection.
type encoder struct {
	sync.Mutex
	buf *bytes.Buffer
	w   *zlib.Writer
}

// NewEncoder is used to create a new encoder.
func NewEncoder() *encoder {
	return new(encoder)
}

// Encode uses zlib compression to compress the provided
// data, according to the SPDY specification of the given version.
func (e *encoder) Encode(h http.Header) ([]byte, error) {
	e.Lock()
	defer e.Unlock()

	// Ensure the buffer is prepared.
	if e.buf == nil {
		e.buf = new(bytes.Buffer)
	} else {
		e.buf.Reset()
	}

	// Ensure the compressor is prepared.
	if e.w == nil {
		var err error
		select {
		case e.w = <-zlibV2Writers:
			e.w.Reset(e.buf)
		default:
			e.w, err = zlib.NewWriterLevelDict(e.buf, zlib.BestCompression, HeaderDictionary)
		}
		if err != nil {
			return nil, err
		}
	}

	var size = 2

	// Remove invalid headers.
	h.Del("Connection")
	h.Del("Keep-Alive")
	h.Del("Proxy-Connection")
	h.Del("Transfer-Encoding")

	length := size                   // The 4-byte or 2-byte number of name/value pairs.
	pairs := make(map[string]string) // Used to store the validated, joined headers.
	for name, values := range h {
		// Ignore invalid names.
		if _, ok := pairs[name]; ok { // We've already seen this name.
			return nil, errors.New("Error: Duplicate header name discovered.")
		}
		if name == "" { // Ignore empty names.
			continue
		}

		// Multiple values are separated by a single null byte.
		pairs[name] = strings.Join(values, "\x00")

		// +size for len(name), +size for len(values).
		length += len(name) + size + len(pairs[name]) + size
	}

	// Uncompressed data.
	out := make([]byte, length)

	// Current offset into out.
	var offset uint32

	// Write the number of name/value pairs.
	num := uint32(len(pairs))
	out[0] = byte(num >> 8)
	out[1] = byte(num)
	offset = 2

	// For each name/value pair...
	for name, value := range pairs {

		// The length of the name.
		nLen := uint32(len(name))
		out[offset+0] = byte(nLen >> 8)
		out[offset+1] = byte(nLen)
		offset += 2

		// The name itself.
		copy(out[offset:], []byte(strings.ToLower(name)))
		offset += nLen

		// The length of the value.
		vLen := uint32(len(value))
		out[offset+0] = byte(vLen >> 8)
		out[offset+1] = byte(vLen)
		offset += 2

		// The value itself.
		copy(out[offset:], []byte(value))
		offset += vLen
	}

	// Compress.
	err := WriteExactly(e.w, out)
	if err != nil {
		return nil, err
	}

	e.w.Flush()
	return e.buf.Bytes(), nil
}

func (e *encoder) Close() error {
	if e.w == nil {
		return nil
	}
	channel := zlibV2Writers
	select {
	case channel <- e.w:
	default:
		err := e.w.Close()
		if err != nil {
			return err
		}
	}
	e.w = nil
	return nil
}

var ErrConnNil = errors.New("Error: Connection is nil.")

// WriteExactly is used to ensure that the given data is written
// if possible, even if multiple calls to Write are
// required.
func WriteExactly(w io.Writer, data []byte) error {
	i := len(data)
	for i > 0 {
		if w == nil {
			return ErrConnNil
		}
		if n, err := w.Write(data); err != nil {
			return err
		} else {
			data = data[n:]
			i -= n
		}
	}
	return nil
}

// ReadExactly is used to ensure that the given number of bytes
// are read if possible, even if multiple calls to Read
// are required.
func ReadExactly(r io.Reader, i int) ([]byte, error) {
	out := make([]byte, i)
	in := out[:]
	for i > 0 {
		if r == nil {
			return nil, ErrConnNil
		}
		if n, err := r.Read(in); err != nil {
			return nil, err
		} else {
			in = in[n:]
			i -= n
		}
	}
	return out, nil
}

func BytesToUint16(b []byte) uint16 {
	return (uint16(b[0]) << 8) + uint16(b[1])
}
