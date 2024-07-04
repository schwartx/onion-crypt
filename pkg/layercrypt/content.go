package layercrypt

import (
	"encoding/binary"
	"errors"
)

var (
	ErrNilContent       = errors.New("content pointer is nil")
	ErrDataTooShort     = errors.New("data too short")
	ErrInsufficientData = errors.New("insufficient data for payload, hint, or RemainingLayers")
)

type Content struct {
	Payload         []byte
	Hint            string
	RemainingLayers int
}

func (c *Content) Serialize() []byte {
	payloadLen := uint32(len(c.Payload))
	hintLen := uint32(len(c.Hint))

	totalLen := 12 + len(c.Payload) + len(c.Hint)
	result := make([]byte, totalLen)

	binary.LittleEndian.PutUint32(result[0:], payloadLen)
	copy(result[4:], c.Payload)
	binary.LittleEndian.PutUint32(result[4+payloadLen:], hintLen)
	copy(result[8+payloadLen:], c.Hint)
	binary.LittleEndian.PutUint32(result[totalLen-4:], uint32(c.RemainingLayers))

	return result
}

func Deserialize(data []byte, content *Content) error {
	if content == nil {
		return ErrNilContent
	}

	if len(data) < 12 {
		return ErrDataTooShort
	}

	payloadLen := binary.LittleEndian.Uint32(data[0:4])
	if len(data) < int(8+payloadLen) {
		return ErrInsufficientData
	}

	hintLen := binary.LittleEndian.Uint32(data[4+payloadLen : 8+payloadLen])
	if len(data) < int(12+payloadLen+hintLen) {
		return ErrInsufficientData
	}

	content.Payload = make([]byte, payloadLen)
	copy(content.Payload, data[4:4+payloadLen])
	content.Hint = string(data[8+payloadLen : 8+payloadLen+hintLen])
	content.RemainingLayers = int(binary.LittleEndian.Uint32(data[len(data)-4:]))

	return nil
}
