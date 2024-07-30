// SPDX-License-Identifier: Apache-2.0

package nbd

import (
	"errors"
	"fmt"
)

var (
	ErrUnsupported       = errors.New("server does not support option")
	ErrPolicy            = errors.New("server forbids option")
	ErrInvalid           = errors.New("invalid option")
	ErrPlatform          = errors.New("server platform does not support option")
	ErrTLSReqd           = errors.New("server requires TLS for option")
	ErrUnknown           = errors.New("requested export is not available")
	ErrShutdown          = errors.New("server is shutting down")
	ErrBlockSizeRequired = errors.New("server requires blocksize assurances from client")
	ErrTooBig            = errors.New("request or reply is too large to process")
	ErrExtHeaderRequired = errors.New("extension header required")
	ErrUndefined         = errors.New("did not understand error type from server")

	ErrPerm              = errors.New("operation not permitted")
	ErrIO                = errors.New("input/output error")
	ErrNoMem             = errors.New("cannot allocate memory")
	ErrInval             = errors.New("invalid argument")
	ErrNoSpc             = errors.New("no space left on device")
	ErrOverflow          = errors.New("value too large for defined data type")
	ErrNotSupported      = errors.New("operation not supported")
	ErrTransportShutdown = errors.New("cannot send after transport endpoint shutdown")
)

type NegotiationError struct {
	Cause   error
	Message string
}

func (e *NegotiationError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("%s: %s", e.Cause.Error(), e.Message)
	}
	return e.Cause.Error()
}

func IsUnsupportedErr(err error) bool       { return isNegotiationErr(err, ErrUnsupported) }
func IsPolicyErr(err error) bool            { return isNegotiationErr(err, ErrPolicy) }
func IsInvalidErr(err error) bool           { return isNegotiationErr(err, ErrInvalid) }
func IsPlatformErr(err error) bool          { return isNegotiationErr(err, ErrPlatform) }
func IsTLSReqdErr(err error) bool           { return isNegotiationErr(err, ErrTLSReqd) }
func IsUnknownErr(err error) bool           { return isNegotiationErr(err, ErrUnknown) }
func IsShutdownErr(err error) bool          { return isNegotiationErr(err, ErrShutdown) }
func IsBlockSizeRequiredErr(err error) bool { return isNegotiationErr(err, ErrBlockSizeRequired) }
func IsErrTooBig(err error) bool            { return isNegotiationErr(err, ErrTooBig) }
func IsExtHeaderRequiredErr(err error) bool { return isNegotiationErr(err, ErrExtHeaderRequired) }
func IsUndefinedErr(err error) bool         { return isNegotiationErr(err, ErrUndefined) }

func isNegotiationErr(err, target error) bool {
	if errors.Is(err, target) {
		return true
	}
	var e *NegotiationError
	if errors.As(err, &e) {
		return errors.Is(e.Cause, target)
	}
	return false
}

type TransmissionError struct {
	Cause     error
	Message   string
	Offset    uint64
	HasOffset bool
}

func (e *TransmissionError) Error() string {
	s := "transmission error"
	if e.HasOffset {
		s = fmt.Sprintf("%s at offset %d: %s", s, e.Offset, e.Cause.Error())
	}
	if e.Message != "" {
		s = s + fmt.Sprintf(": %s", e.Message)
	}
	return s
}

func IsPermErr(err error) bool              { return isTransmissionErr(err, ErrPerm) }
func IsIOErr(err error) bool                { return isTransmissionErr(err, ErrIO) }
func IsNoMemErr(err error) bool             { return isTransmissionErr(err, ErrNoMem) }
func IsInvalErr(err error) bool             { return isTransmissionErr(err, ErrInval) }
func IsNoSpcErr(err error) bool             { return isTransmissionErr(err, ErrNoSpc) }
func IsOverflowErr(err error) bool          { return isTransmissionErr(err, ErrOverflow) }
func IsNotSupportedErr(err error) bool      { return isTransmissionErr(err, ErrNotSupported) }
func IsTransportShutdownErr(err error) bool { return isTransmissionErr(err, ErrTransportShutdown) }

func isTransmissionErr(err, target error) bool {
	if errors.Is(err, target) {
		return true
	}
	var e *TransmissionError
	if errors.As(err, &e) {
		return errors.Is(e.Cause, target)
	}
	return false
}
