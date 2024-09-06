// SPDX-License-Identifier: Apache-2.0

package nbd

import (
	"fmt"

	"github.com/digitalocean/go-nbd/internal/nbdproto"
)

type OptionErrorCode uint32

const (
	ErrUnsupported       = OptionErrorCode(nbdproto.REP_ERR_UNSUPPORTED)
	ErrPolicy            = OptionErrorCode(nbdproto.REP_ERR_POLICY)
	ErrInvalid           = OptionErrorCode(nbdproto.REP_ERR_INVALID)
	ErrPlatform          = OptionErrorCode(nbdproto.REP_ERR_PLATFORM)
	ErrTLSRequired       = OptionErrorCode(nbdproto.REP_ERR_TLS_REQUIRED)
	ErrUnknown           = OptionErrorCode(nbdproto.REP_ERR_UNKNOWN)
	ErrShutdown          = OptionErrorCode(nbdproto.REP_ERR_SHUTDOWN)
	ErrBlockSizeRequired = OptionErrorCode(nbdproto.REP_ERR_BLOCK_SIZE_REQUIRED)
	ErrTooBig            = OptionErrorCode(nbdproto.REP_ERR_TOO_BIG)
	ErrExtHeaderRequired = OptionErrorCode(nbdproto.REP_ERR_EXT_HEADER_REQUIRED)
)

func (o OptionErrorCode) Symbol() string {
	switch o {
	case ErrUnsupported:
		return "REP_ERR_UNSUPPORTED"
	case ErrPolicy:
		return "REP_ERR_POLICY"
	case ErrInvalid:
		return "REP_ERR_INVALID"
	case ErrPlatform:
		return "REP_ERR_PLATFORM"
	case ErrTLSRequired:
		return "REP_ERR_TLS_REQUIRED"
	case ErrUnknown:
		return "REP_ERR_UNKNOWN"
	case ErrShutdown:
		return "REP_ERR_SHUTDOWN"
	case ErrBlockSizeRequired:
		return "REP_ERR_BLOCK_SIZE_REQUIRED"
	case ErrTooBig:
		return "REP_ERR_TOO_BIG"
	case ErrExtHeaderRequired:
		return "REP_ERR_EXT_HEADER_REQUIRED"
	default:
		return fmt.Sprintf("BUG:%d", uint32(o))
	}
}

// NegotiationError is a protocol-level error returned by the server
// during the option phase.
type NegotiationError struct {
	Code    OptionErrorCode
	Message NullErrorMessage
}

func (e *NegotiationError) Error() string {
	if e.Message.Valid {
		return fmt.Sprintf("%s: %s", e.Message.Value, e.Code.Symbol())
	}
	return e.Code.Symbol()
}

type TransmissionErrorCode uint32

const (
	ErrNotPermitted    = TransmissionErrorCode(nbdproto.EPERM)
	ErrIO              = TransmissionErrorCode(nbdproto.EIO)
	ErrNoMemory        = TransmissionErrorCode(nbdproto.ENOMEM)
	ErrInvalidArgument = TransmissionErrorCode(nbdproto.EINVAL)
	ErrNoSpaceLeft     = TransmissionErrorCode(nbdproto.ENOSPC)
	ErrOverflow        = TransmissionErrorCode(nbdproto.EOVERFLOW)
	ErrNotSupported    = TransmissionErrorCode(nbdproto.ENOTSUP)
	ErrShuttingDown    = TransmissionErrorCode(nbdproto.ESHUTDOWN)
)

func (t TransmissionErrorCode) Symbol() string {
	switch t {
	case ErrNotPermitted:
		return "EPERM"
	case ErrIO:
		return "EIO"
	case ErrNoMemory:
		return "ENOMEM"
	case ErrInvalidArgument:
		return "EINVAL"
	case ErrNoSpaceLeft:
		return "ENOSPC"
	case ErrOverflow:
		return "EOVERFLOW"
	case ErrNotSupported:
		return "ENOTSUP"
	case ErrShuttingDown:
		return "ESHUTDOWN"
	default:
		return fmt.Sprintf("BUG:%d", uint32(t))
	}
}

// TransmissionError is a protocol-level error returned by the server
// during the transmission phase.
type TransmissionError struct {
	Code    TransmissionErrorCode
	Message NullErrorMessage
	Offset  NullOffset
}

func (e *TransmissionError) Error() string {
	if e.Message.Valid {
		return fmt.Sprintf("%s: %s", e.Message.Value, e.Code.Symbol())
	}
	return e.Code.Symbol()
}

type NullErrorMessage struct {
	Value string
	Valid bool
}

type NullOffset struct {
	Value uint64
	Valid bool
}
