package spdy

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// http://www.chromium.org/spdy/spdy-protocol/spdy-protocol-draft2#TOC-Framing
const frameHeaderLen = 8

// // A FrameType is a registered frame type as defined in
// // http://www.chromium.org/spdy/spdy-protocol/spdy-protocol-draft2#TOC-Control-frames
type FrameType uint16

const (
	FrameSYNStream FrameType = 0x1
	FrameSYNReply  FrameType = 0x2
	FrameRSTStream FrameType = 0x3
	FrameSettings  FrameType = 0x4
	FrameNOOP      FrameType = 0x5
	FramePing      FrameType = 0x6
	FrameGoAway    FrameType = 0x7
	FrameHeaders   FrameType = 0x8
)

var frameName = map[FrameType]string{
	FrameSYNStream: "SYN_STREAM",
	FrameSYNReply:  "SYN_REPLY",
	FrameRSTStream: "RST_STREAM",
	FrameSettings:  "SETTINGS",
	FrameNOOP:      "NOOP",
	FramePing:      "PING",
	FrameGoAway:    "GOAWAY",
	FrameHeaders:   "HEADERS",
}

func (t FrameType) String() string {
	if s, ok := frameName[t]; ok {
		return s
	}
	return fmt.Sprintf("UNKNOWN_FRAME_TYPE_%d", uint8(t))
}

// Flags is a bitmask of SPDY flags.
// The meaning of flags varies depending on the frame type.
type Flags uint8

// Has reports whether f contains all (0 or more) flags in v.
func (f Flags) Has(v Flags) bool {
	return (f & v) == v
}

const (
	FlagFin            Flags = 0x1
	FlagUnidirectional Flags = 0x2

	// Settings Frame
	FlagSettingsClearPreviouslyPersistedSettings Flags = 0x1
	FlagSettingsPersistValue                     Flags = 0x1
	FlagSettingsPersisted                        Flags = 0x2
)

var flagName = map[FrameType]map[Flags]string{
	FrameSYNStream: {
		FlagFin:            "FLAG_FIN",
		FlagUnidirectional: "FLAG_UNIDIRECTIONAL",
	},
	FrameSYNReply: {
		FlagFin: "FLAG_FIN",
	},
	FrameSettings: {
		FlagSettingsPersistValue: "FLAG_SETTINGS_PERSIST_VALUE",
		FlagSettingsPersisted:    "FLAG_SETTINGS_PERSISTED",
	},
}

// a frameParser parses a frame given its FrameHeader and payload
// bytes. The length of payload will always equal fh.Length (which
// might be 0).
type frameParser func(fr *Framer, fh FrameHeader, payload []byte) (Frame, error)

var frameParsers = map[FrameType]frameParser{
	FrameSettings: parseSettingsFrame,
	FrameSYNReply: parseSynReplyFrame,
	FrameGoAway:   parseGoAwayFrame,
	FrameNOOP:     parseNoopFrame,
}

func typeFrameParser(t FrameType) frameParser {
	if f := frameParsers[t]; f != nil {
		return f
	}
	return parseUnknownFrame
}

// A FrameHeader is the 8 byte header of all SPDY control frames.
//
// See http://www.chromium.org/spdy/spdy-protocol/spdy-protocol-draft2#TOC-Control-frames
// +----------------------------------+
// |C| Version(15bits) | Type(16bits) |
// +----------------------------------+
// | Flags (8)  |  Length (24 bits)   |
// +----------------------------------+
// |               Data               |
// +----------------------------------+
type FrameHeader struct {
	valid bool // caller can access []byte fields in the Frame

	// Type is the 2 byte frame type. There are 8 standard control frame
	// types.
	Type FrameType

	// Flags are the 1 byte of 8 potential bit flags per frame.
	// They are specific to the frame type.
	Flags Flags

	// Length is the length of the frame, not including the 8 byte header.
	// The maximum size is one byte less than 16MB (uint24), but only
	// frames up to 16KB are allowed without peer agreement.
	Length uint32
}

// Header returns h. It exists so FrameHeaders can be embedded in other
// specific frame types and implement the Frame interface.
func (h FrameHeader) Header() FrameHeader { return h }

func (h FrameHeader) String() string {
	var buf bytes.Buffer
	buf.WriteString("[FrameHeader ")
	buf.WriteString(h.Type.String())
	if h.Flags != 0 {
		buf.WriteString(" flags=")
		set := 0
		for i := uint8(0); i < 8; i++ {
			if h.Flags&(1<<i) == 0 {
				continue
			}
			set++
			if set > 1 {
				buf.WriteByte('|')
			}
			name := flagName[h.Type][Flags(1<<i)]
			if name != "" {
				buf.WriteString(name)
			} else {
				fmt.Fprintf(&buf, "0x%x", 1<<i)
			}
		}
	}
	fmt.Fprintf(&buf, " len=%d]", h.Length)
	return buf.String()
}

func (h *FrameHeader) checkValid() {
	if !h.valid {
		panic("Frame accessor called on non-owned Frame")
	}
}

func (h *FrameHeader) invalidate() { h.valid = false }

// readFrameHeader reads the common Control Frame Header
// +----------------------------------+
// |C| Version(15bits) | Type(16bits) |
// +----------------------------------+
// | Flags (8)  |  Length (24 bits)   |
// +----------------------------------+
func (fr *Framer) readFrameHeader(buf []byte, r io.Reader) (FrameHeader, error) {
	_, err := io.ReadFull(r, buf[:frameHeaderLen])
	if err != nil {
		return FrameHeader{}, err
	}

	version := (uint16(buf[0]&0x7f) << 8) | uint16(buf[1])
	if version != 2 {
		return FrameHeader{}, notImplemented()
	}

	return FrameHeader{
		Length: fr.readUint24(buf[5:]),
		Type:   FrameType(fr.readUint16(buf[2:4])),
		Flags:  Flags(buf[4]),
		valid:  true,
	}, nil
}

// A Frame is the base interface implemented by all frame types.
// Callers will generally type-assert the specific frame type:
// *HeadersFrame, *SettingsFrame, *WindowUpdateFrame, etc.
//
// Frames are only valid until the next call to Framer.ReadFrame.
type Frame interface {
	Header() FrameHeader

	// invalidate is called by Framer.ReadFrame to make this
	// frame's buffers as being invalid, since the subsequent
	// frame will reuse them.
	invalidate()
}

// A Framer reads and writes Frames.
type Framer struct {
	br        *bufio.Reader
	lastFrame Frame

	maxReadSize uint32
	headerBuf   [frameHeaderLen]byte

	// TODO: let getReadBuf be configurable, and use a less memory-pinning
	// allocator in server.go to minimize memory pinned for many idle conns.
	// Will probably also need to make frame invalidation have a hook too.
	getReadBuf func(size uint32) []byte
	readBuf    []byte // cache for default getReadBuf

	maxWriteSize uint32 // zero means unlimited; TODO: implement

	bw   *bufio.Writer
	wbuf []byte

	// AllowIllegalWrites permits the Framer's Write methods to
	// write frames that do not conform to the HTTP/2 spec.  This
	// permits using the Framer to test other HTTP/2
	// implementations' conformance to the spec.
	// If false, the Write methods will prefer to return an error
	// rather than comply.
	AllowIllegalWrites bool

	// TODO: track which type of frame & with which flags was sent
	// last.  Then return an error (unless AllowIllegalWrites) if
	// we're in the middle of a header block and a
	// non-Continuation or Continuation on a different stream is
	// attempted to be written.
}

// +----------------------------------+
// |C| Version(15bits) | Type(16bits) |
// +----------------------------------+
// | Flags (8)  |  Length (24 bits)   |
// +----------------------------------+
func (f *Framer) startWrite(ftype FrameType, flags Flags) {
	// Write the FrameHeader.
	f.wbuf = append(f.wbuf[:0],
		1<<7, // Control bit
		2,    // 15 bits version
		0,    // 16 bits type
		byte(ftype),
		byte(flags), // 8 bits flags
		0,           // 3 bytes of length, filled in by endWrite
		0,
		0)
}

func (f *Framer) endWrite() error {
	// Now that we know the final size, fill in the FrameHeader in
	// the space previously reserved for it. Abuse append.
	length := len(f.wbuf) - frameHeaderLen
	if length >= MAX_FRAME_SIZE {
		return ErrFrameTooLarge
	}
	_ = append(f.wbuf[:5],
		byte(length>>16),
		byte(length>>8),
		byte(length))

	// log.Printf("Sending header\t%q\n", f.wbuf[:8])
	// log.Printf("Sending data\t%q\n", f.wbuf[8:])

	n, err := f.bw.Write(f.wbuf)
	if err == nil && n != len(f.wbuf) {
		err = io.ErrShortWrite
	}
	return err
}

func (f *Framer) writeByte(v byte)    { f.wbuf = append(f.wbuf, v) }
func (f *Framer) writeBytes(v []byte) { f.wbuf = append(f.wbuf, v...) }

func (f *Framer) writeUint32(v uint32) {
	f.wbuf = append(f.wbuf, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func (f *Framer) readUint16(b []byte) uint16 {
	return binary.BigEndian.Uint16(b)
}

func (f *Framer) readUint24(b []byte) uint32 {
	return ReadUint24(b)
}

func ReadUint24(b []byte) uint32 {
	return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
}

func (f *Framer) readUint32(b []byte) uint32 {
	return ReadUint32(b)
}

func ReadUint32(b []byte) uint32 {
	return binary.BigEndian.Uint32(b)
}

const (
	minMaxFrameSize = 1 << 14
	maxFrameSize    = 1<<24 - 1
)

// NewFramer returns a Framer that writes frames to w and reads them from r.
func NewFramer(bw *bufio.Writer, br *bufio.Reader) *Framer {
	fr := &Framer{
		bw: bw,
		br: br,
	}
	fr.getReadBuf = func(size uint32) []byte {
		if cap(fr.readBuf) >= int(size) {
			return fr.readBuf[:size]
		}
		fr.readBuf = make([]byte, size)
		return fr.readBuf
	}
	fr.SetMaxReadFrameSize(maxFrameSize)
	return fr
}

// SetMaxReadFrameSize sets the maximum size of a frame
// that will be read by a subsequent call to ReadFrame.
// It is the caller's responsibility to advertise this
// limit with a SETTINGS frame.
func (fr *Framer) SetMaxReadFrameSize(v uint32) {
	if v > maxFrameSize {
		v = maxFrameSize
	}
	fr.maxReadSize = v
}

// ErrFrameTooLarge is returned from Framer.ReadFrame when the peer
// sends a frame that is larger than declared with SetMaxReadFrameSize.
var ErrFrameTooLarge = errors.New("spdy: frame too large")

// ReadFrame reads a single frame. The returned Frame is only valid
// until the next call to ReadFrame.
// If the frame is larger than previously set with SetMaxReadFrameSize,
// the returned error is ErrFrameTooLarge.
func (fr *Framer) ReadFrame() (Frame, error) {
	if fr.lastFrame != nil {
		fr.lastFrame.invalidate()
	}
	start, err := fr.br.Peek(4)

	// log.Printf("Reading a response\n")

	if err != nil {
		return nil, err
	}

	// log.Printf("Checking the response type\n")

	if start[0] != 128 {
		return fr.parseDataFrame(fr.headerBuf[:], fr.br)
	}

	// log.Printf("Got CONTROL FRAME %s\n", FrameType(fr.readUint16(start[2:4])))

	// readFrameHeader – control frames have a common format
	fh, err := fr.readFrameHeader(fr.headerBuf[:], fr.br)
	// log.Printf("Got %v\n", fh)
	if err != nil {
		return nil, err
	}
	if fh.Length > fr.maxReadSize {
		return nil, ErrFrameTooLarge
	}
	payload := fr.getReadBuf(fh.Length)
	if _, err := io.ReadFull(fr.br, payload); err != nil {
		return nil, err
	}
	f, err := typeFrameParser(fh.Type)(fr, fh, payload)
	if err != nil {
		return nil, err
	}
	fr.lastFrame = f
	return f, nil
}

// A DataFrame conveys arbitrary, variable-length sequences of octets
// associated with a stream.
// See http://www.chromium.org/spdy/spdy-protocol/spdy-protocol-draft2#TOC-Data-frames
type DataFrame struct {
	FrameHeader
	StreamID uint32
	Length   uint32
	data     []byte
}

func (f *DataFrame) StreamEnded() bool {
	return f.FrameHeader.Flags.Has(FlagFin)
}

// Data returns the frame's data octets, not including any padding
// size byte or padding suffix bytes.
// The caller must not retain the returned memory past the next
// call to ReadFrame.
func (f *DataFrame) Data() []byte {
	f.checkValid()
	return f.data
}

//  +----------------------------------+
//  |C|       Stream-ID (31bits)       |
//  +----------------------------------+
//  | Flags (8)  |  Length (24 bits)   |
//  +----------------------------------+
//  |               Data               |
//  +----------------------------------+
func (fr *Framer) parseDataFrame(buf []byte, r io.Reader) (Frame, error) {
	_, err := io.ReadFull(r, buf[:frameHeaderLen])
	if err != nil {
		return nil, err
	}

	// log.Printf("Got DATA FRAME %#v\n", buf)
	streamID := fr.readUint32(buf[0:4])
	flags := Flags(buf[4])
	length := fr.readUint24(buf[5:])
	payload := fr.getReadBuf(length)

	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}

	f := &DataFrame{StreamID: streamID, data: payload}
	f.Flags = flags
	f.Length = length
	f.valid = true
	return f, nil
}

var errStreamID = errors.New("invalid streamid")

func validStreamID(streamID uint32) bool {
	return streamID != 0 && streamID&(1<<31) == 0
}

// WriteData writes a DATA frame.
//
// It will perform exactly one Write to the underlying Writer.
// It is the caller's responsibility to not call other Write methods concurrently.
func (f *Framer) WriteData(streamID uint32, endStream bool, data []byte) error {
	return notImplemented()
}

// A SettingsFrame conveys configuration parameters that affect how
// endpoints communicate, such as preferences and constraints on peer
// behavior.
//
// See http://www.chromium.org/spdy/spdy-protocol/spdy-protocol-draft2#TOC-SETTINGS
type SettingsFrame struct {
	FrameHeader
	p []byte
}

// +----------------------------------+
// |1|       2          |       4     |
// +----------------------------------+
// | Flags (8)  |  Length (24 bits)   |
// +----------------------------------+
// |         Number of entries        |
// +----------------------------------+
// |          ID/Value Pairs          |
// |             ...                  |
func parseSettingsFrame(fr *Framer, fh FrameHeader, p []byte) (Frame, error) {
	numSettings := fr.readUint32(p[0:4])

	// Frame length should be 8 bytes for each setting, + 4 bytes for the uint32 that is the number of settings
	if fh.Length != (8*numSettings)+4 {
		return nil, ConnectionError(ErrCodeProtocol)
	}

	f := &SettingsFrame{FrameHeader: fh, p: p[4:]}

	// log.Printf("Checking %v, length: %d\n", f, len(f.p))

	if v, ok := f.Value(SettingInitialWindowSize); ok && v > (1<<31)-1 {
		// Values above the maximum flow control window size of 2^31 MUST be treated as a connection error
		return nil, ConnectionError(ErrCodeFlowControl)
	}

	// log.Printf("Parsed the SettingsFrame\n")

	return f, nil
}

func (f *SettingsFrame) Value(s SettingID) (v uint32, ok bool) {
	f.checkValid()
	buf := f.p
	for len(buf) > 0 {
		settingID := f.readSettingID(buf[:3])
		if settingID == s {
			return ReadUint32(buf[4:8]), true
		}
		buf = buf[8:]
	}
	return 0, false
}

// readSettingID encapsulates reading a SettingID from 3 bytes.
//
// "24-bits in little-endian byte order.  This is inconsistent with other
// values in SPDY and is the result of a bug in the initial v2 implementation.""
func (f *SettingsFrame) readSettingID(b []byte) SettingID {
	return SettingID(uint32(b[2])<<16 | uint32(b[1])<<8 | uint32(b[0]))
}

// writeSettingID encapsulates writing a SettingID.
//
// "24-bits in little-endian byte order.  This is inconsistent with other
// values in SPDY and is the result of a bug in the initial v2 implementation.""
func (f *Framer) writeSettingID(ID SettingID) {
	f.wbuf = append(f.wbuf, byte(ID), byte(ID>>8), byte(ID>>16))
}

// ForeachSetting runs fn for each setting.
// It stops and returns the first error.
func (f *SettingsFrame) ForeachSetting(fn func(Setting) error) error {
	f.checkValid()
	buf := f.p
	for len(buf) > 0 {
		if err := fn(Setting{
			f.readSettingID(buf[:3]),
			Flags(buf[3]),
			binary.BigEndian.Uint32(buf[4:8]),
		}); err != nil {
			return err
		}
		buf = buf[8:]
	}
	return nil
}

// WriteSettings writes a SETTINGS frame with zero or more settings
// specified.
//
// It will perform exactly one Write to the underlying Writer.
// It is the caller's responsibility to not call other Write methods concurrently.
//
// +----------------------------------+
// |1|       2          |       4     |
// +----------------------------------+
// | Flags (8)  |  Length (24 bits)   |
// +----------------------------------+
// |         Number of entries        |
// +----------------------------------+
// |          ID/Value Pairs          |
// |             ...                  |
func (f *Framer) WriteSettings(settings ...Setting) error {
	numSettings := uint32(len(settings))
	f.startWrite(FrameSettings, 0)
	f.writeUint32(numSettings)
	for _, s := range settings {
		f.writeSetting(s)
	}
	return f.endWrite()
	// return nil
}

// +----------------------------------+
// |    ID (24 bits)   | ID_Flags (8) |
// +----------------------------------+
// |          Value (32 bits)         |
// +----------------------------------+
func (f *Framer) writeSetting(s Setting) {
	// log.Printf("Writing setting %s\n", s.ID.String())
	f.writeSettingID(s.ID)
	f.writeByte(byte(s.Flags))
	f.writeUint32(s.Val)
}

type SynStreamFrame struct {
	FrameHeader
	StreamID uint32
	Headers  []byte
}

//  +----------------------------------+
//  |1|       2          |       1     |
//  +----------------------------------+
//  | Flags (8)  |  Length (24 bits)   |
//  +----------------------------------+
//  |X|          Stream-ID (31bits)    |
//  +----------------------------------+
//  |X|Associated-To-Stream-ID (31bits)|
//  +----------------------------------+
//  | Pri (2bits) | Unused (14 bits)   |
//  +------------------                |
//  |     Name/value header block      |
//  |             ...                  |
func (f *Framer) WriteSynStream(syn SynStreamFrame) error {
	if !validStreamID(syn.StreamID) {
		return errStreamID
	}
	f.startWrite(FrameSYNStream, syn.Flags)
	f.writeUint32(syn.StreamID)     // Stream ID
	f.writeUint32(0)                // TODO(jabley): Associated Stream ID
	f.writeByte(byte((2 & 3) << 6)) // Priority and Unused
	f.writeByte(0)                  // Unused
	f.writeBytes(syn.Headers)
	return f.endWrite()
}

type SynReplyFrame struct {
	FrameHeader
	StreamID uint32
	Headers  []byte
}

// +----------------------------------+
// |1|        2        |        2     |
// +----------------------------------+
// | Flags (8)  |  Length (24 bits)   |
// +----------------------------------+
// |X|          Stream-ID (31bits)    |
// +----------------------------------+
// | Unused(16bits)|                  |
// +----------------                  |
// |     Name/value header block      |
// |              ...                 |
func parseSynReplyFrame(fr *Framer, fh FrameHeader, p []byte) (Frame, error) {
	return &SynReplyFrame{StreamID: fr.readUint32(p[0:4]), Headers: p[6:]}, nil
}

func (sr *SynReplyFrame) StreamEnded() bool {
	return sr.Flags.Has(FlagFin)
}

// A GoAwayFrame informs the remote peer to stop creating streams on this connection.
// http://www.chromium.org/spdy/spdy-protocol/spdy-protocol-draft2#TOC-GOAWAY
type GoAwayFrame struct {
	FrameHeader
	LastStreamID uint32
}

// +----------------------------------+
// |1|       2          |       7     |
// +----------------------------------+
// | 0 (flags) |     4 (length)       |
// +----------------------------------|
// |X|  Last-good-stream-ID (31 bits) |
// +----------------------------------+
func parseGoAwayFrame(fr *Framer, fh FrameHeader, p []byte) (Frame, error) {
	return &GoAwayFrame{LastStreamID: fr.readUint32(p)}, nil
}

// A NoopFrame can be ignored.
// http://www.chromium.org/spdy/spdy-protocol/spdy-protocol-draft2#TOC-NOOP
type NoopFrame struct {
	FrameHeader
}

// +----------------------------------+
// |1|       2          |       5     |
// +----------------------------------+
// | 0 (Flags)  |    0 (Length)       |
// +----------------------------------+
func parseNoopFrame(fr *Framer, fh FrameHeader, p []byte) (Frame, error) {
	return &NoopFrame{}, nil
}

// An UnknownFrame is the frame type returned when the frame type is unknown
// or no specific frame type parser exists.
type UnknownFrame struct {
	FrameHeader
	p []byte
}

// Payload returns the frame's payload (after the header).  It is not
// valid to call this method after a subsequent call to
// Framer.ReadFrame, nor is it valid to retain the returned slice.
// The memory is owned by the Framer and is invalidated when the next
// frame is read.
func (f *UnknownFrame) Payload() []byte {
	f.checkValid()
	return f.p
}

func parseUnknownFrame(fr *Framer, fh FrameHeader, p []byte) (Frame, error) {
	return &UnknownFrame{fh, p}, nil
}

type streamEnder interface {
	StreamEnded() bool
}

type headersEnder interface {
	HeadersEnded() bool
}
