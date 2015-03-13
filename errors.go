package spdy

import "fmt"

// An ErrCode is an unsigned 32-bit error code as defined in the HTTP/2 spec.
type ErrCode uint32

const (
	ErrCodeNo                 ErrCode = 0x0
	ErrCodeProtocol           ErrCode = 0x1
	ErrCodeInvalidStream      ErrCode = 0x2
	ErrCodeRefusedStream      ErrCode = 0x3
	ErrCodeUnsupportedVersion ErrCode = 0x4
	ErrCodeCancel             ErrCode = 0x5
	ErrCodeInternal           ErrCode = 0x6
	ErrCodeFlowControl        ErrCode = 0x7
)

var errCodeName = map[ErrCode]string{
	ErrCodeNo:                 "NO_ERROR",
	ErrCodeProtocol:           "PROTOCOL_ERROR",
	ErrCodeInvalidStream:      "INVALID_STREAM",
	ErrCodeRefusedStream:      "REFUSED_STREAM",
	ErrCodeUnsupportedVersion: "UNSUPPORTED_VERSION",
	ErrCodeCancel:             "CANCEL",
	ErrCodeInternal:           "INTERNAL_ERROR",
	ErrCodeFlowControl:        "FLOW_CONTROL_ERROR",
}

func (e ErrCode) String() string {
	if s, ok := errCodeName[e]; ok {
		return s
	}
	return fmt.Sprintf("unknown error code 0x%x", uint32(e))
}

// ConnectionError is an error that results in the termination of the
// entire connection.
type ConnectionError ErrCode

func (e ConnectionError) Error() string { return fmt.Sprintf("connection error: %s", ErrCode(e)) }

// StreamError is an error that only affects one stream within an
// HTTP/2 connection.
type StreamError struct {
	StreamID uint32
	Code     ErrCode
}

func (e StreamError) Error() string {
	return fmt.Sprintf("stream error: stream ID %d; %v", e.StreamID, e.Code)
}
