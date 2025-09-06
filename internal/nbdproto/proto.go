// SPDX-License-Identifier: Apache-2.0

package nbdproto

const (
	NBD_MAGIC                  uint64 = 0x4e42444d41474943
	HAVE_OPT                   uint64 = 0x49484156454F5054
	CLI_SERV                   uint64 = 0x00420281861253
	REQUEST_MAGIC              uint32 = 0x25609513
	NBD_SIMPLE_REPLY_MAGIC     uint32 = 0x67446698
	NBD_STRUCTURED_REPLY_MAGIC uint32 = 0x668e33ef

	FLAG_FIXED_NEWSTYLE uint16 = 1 << 0
	FLAG_NO_ZEROES      uint16 = 1 << 1

	FLAG_HAS_FLAGS            uint16 = 1 << 0
	FLAG_READ_ONLY            uint16 = 1 << 1
	FLAG_SEND_FLUSH           uint16 = 1 << 2
	FLAG_SEND_FUA             uint16 = 1 << 3
	FLAG_ROTATIONAL           uint16 = 1 << 4
	FLAG_SEND_TRIM            uint16 = 1 << 5
	FLAG_SEND_WRITE_ZEROES    uint16 = 1 << 6
	FLAG_SEND_DF              uint16 = 1 << 7
	FLAG_CAN_MULTI_CONN       uint16 = 1 << 8
	FLAG_SEND_RESIZE          uint16 = 1 << 9
	FLAG_SEND_CACHE           uint16 = 1 << 10
	FLAG_SEND_FAST_ZERO       uint16 = 1 << 11
	FLAG_BLOCK_STATUS_PAYLOAD uint16 = 1 << 12

	OPT_EXPORT_NAME       uint32 = 1
	OPT_ABORT             uint32 = 2
	OPT_LIST              uint32 = 3
	OPT_STARTTLS          uint32 = 5
	OPT_INFO              uint32 = 6
	OPT_GO                uint32 = 7
	OPT_STRUCTURED_REPLY  uint32 = 8
	OPT_LIST_META_CONTEXT uint32 = 9
	OPT_SET_META_CONTEXT  uint32 = 10

	REP_ACK    uint32 = 1
	REP_SERVER uint32 = 2
	REP_INFO   uint32 = 3
	REP_META   uint32 = 4

	INFO_EXPORT      uint16 = 0
	INFO_NAME        uint16 = 1
	INFO_DESCRIPTION uint16 = 2
	INFO_BLOCK_SIZE  uint16 = 3

	REP_ERR_UNSUPPORTED         uint32 = (1<<31 | 1)
	REP_ERR_POLICY              uint32 = (1<<31 | 2)
	REP_ERR_INVALID             uint32 = (1<<31 | 3)
	REP_ERR_PLATFORM            uint32 = (1<<31 | 4)
	REP_ERR_TLS_REQUIRED        uint32 = (1<<31 | 5)
	REP_ERR_UNKNOWN             uint32 = (1<<31 | 6)
	REP_ERR_SHUTDOWN            uint32 = (1<<31 | 7)
	REP_ERR_BLOCK_SIZE_REQUIRED uint32 = (1<<31 | 8)
	REP_ERR_TOO_BIG             uint32 = (1<<31 | 9)
	REP_ERR_EXT_HEADER_REQUIRED uint32 = (1<<31 | 10)

	CMD_READ         uint16 = 0
	CMD_WRITE        uint16 = 1
	CMD_DISC         uint16 = 2
	CMD_FLUSH        uint16 = 3
	CMD_TRIM         uint16 = 4
	CMD_CACHE        uint16 = 5
	CMD_WRITE_ZEROES uint16 = 6
	CMD_BLOCK_STATUS uint16 = 7
	CMD_RESIZE       uint16 = 8

	REPLY_FLAG_DONE uint16 = 1 << 0

	REPLY_TYPE_NONE             uint16 = 0
	REPLY_TYPE_OFFSET_DATA      uint16 = 1
	REPLY_TYPE_OFFSET_HOLE      uint16 = 2
	REPLY_TYPE_BLOCK_STATUS     uint16 = 5
	REPLY_TYPE_BLOCK_STATUS_EXT uint16 = 6

	REPLY_TYPE_ERROR        uint16 = (1<<15 | 1)
	REPLY_TYPE_ERROR_OFFSET uint16 = (1<<15 | 2)

	EPERM     uint32 = 1
	EIO       uint32 = 5
	ENOMEM    uint32 = 12
	EINVAL    uint32 = 22
	ENOSPC    uint32 = 28
	EOVERFLOW uint32 = 75
	ENOTSUP   uint32 = 95
	ESHUTDOWN uint32 = 108
)

const MaximumStringLength = 4096

type NegotiationHeader struct {
	Magic   uint64
	Version uint64
}

type OptionHeader struct {
	Magic  uint64
	ID     uint32
	Length uint32
}

type OptionReplyHeader struct {
	Magic  uint64
	ID     uint32
	Type   uint32
	Length uint32
}

type RequestHeader struct {
	Magic  uint32
	Flags  uint16
	Type   uint16
	Cookie uint64
	Offset uint64
	Length uint32
}

type SimpleReplyHeader struct {
	Magic  uint32
	Error  uint32
	Cookie uint64
}

type StructuredReplyHeader struct {
	Magic  uint32
	Flags  uint16
	Type   uint16
	Cookie uint64
	Length uint32
}
