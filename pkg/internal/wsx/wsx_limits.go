package wsx

import "errors"

// MaxFrameSize caps a single frame and a reassembled message. The 64-bit
// length field used to go straight into make([]byte, length): a peer could
// crash the process (makeslice panic) or force a multi-GB allocation with a
// 10-byte header. 64 MiB still fits large CDP messages (base64 screenshots).
var MaxFrameSize uint64 = 64 << 20

// ErrFrameTooLarge is returned when a frame or message exceeds MaxFrameSize.
var ErrFrameTooLarge = errors.New("wsx: frame too large")
