package util

import "log"

type BytePool struct {
	pool  chan []byte
	width int
}

func NewBytePool(width int, depth int) *BytePool {
	return &BytePool{
		pool:  make(chan []byte, depth),
		width: width,
	}
}

func (p *BytePool) Close() {
	close(p.pool)
}

func (p *BytePool) Get() (b []byte) {
	select {
	case b = <-p.pool:
	default:
		b = make([]byte, p.width)
	}
	return b
}

func (p *BytePool) Put(b []byte) {
	// avoid panic: send on closed channel in case we're still processing
	// packets when the channel is closed
	defer func() {
		if err := recover(); err != nil {
			log.Printf("bytepool: %v", err)
		}
	}()

	select {
	case p.pool <- b:
	default:
	}
}
