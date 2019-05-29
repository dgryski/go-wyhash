package wyhash

import (
	"encoding/binary"
	"math/bits"
)

const (
	wyp0 = 0xa0761d6478bd642f
	wyp1 = 0xe7037ed1a0b428db
	wyp2 = 0x8ebc6af09c88c6e3
	wyp3 = 0x589965cc75374cc3
	wyp4 = 0x1d8e4e27c47d124f
	wyp5 = 0xeb44accab455d165
)

func wymum(A, B uint64) uint64 {
	hi, lo := bits.Mul64(A, B)
	return hi ^ lo
}

func wyr64x32(p []byte) uint64 { return wyr32(p)<<32 | wyr32(p[4:]) }
func wyr64(p []byte) uint64    { return binary.LittleEndian.Uint64(p[:8]) }
func wyr32(p []byte) uint64    { return uint64(binary.LittleEndian.Uint32(p[:4])) }
func wyr16(p []byte) uint64    { return uint64(binary.LittleEndian.Uint16(p[:2])) }
func wyr08(p []byte) uint64    { return uint64(p[0]) }

func Hash(key []byte, seed uint64) uint64 {
	p := key

	for len(p) >= 32 {
		seed = wymum(seed^wyp0, wymum(wyr64(p)^wyp1, wyr64(p[8:])^wyp2)^wymum(wyr64(p[16:])^wyp3, wyr64(p[24:])^wyp4))
		p = p[32:]
	}

	seed ^= wyp0
	switch len(key) & 31 {
	case 1:
		seed = wymum(seed, wyr08(p)^wyp1)
	case 2:
		seed = wymum(seed, wyr16(p)^wyp1)
	case 3:
		seed = wymum(seed, ((wyr16(p)<<8)|wyr08(p[2:]))^wyp1)
	case 4:
		seed = wymum(seed, wyr32(p)^wyp1)
	case 5:
		seed = wymum(seed, ((wyr32(p)<<8)|wyr08(p[4:]))^wyp1)
	case 6:
		seed = wymum(seed, ((wyr32(p)<<16)|wyr16(p[4:]))^wyp1)
	case 7:
		seed = wymum(seed, ((wyr32(p)<<24)|(wyr16(p[4:])<<8)|wyr08(p[6:]))^wyp1)
	case 8:
		seed = wymum(seed, wyr64x32(p)^wyp1)
	case 9:
		seed = wymum(wyr64x32(p)^seed, wyr08(p[8:])^wyp2)
	case 10:
		seed = wymum(wyr64x32(p)^seed, wyr16(p[8:])^wyp2)
	case 11:
		seed = wymum(wyr64x32(p)^seed, ((wyr16(p[8:])<<8)|wyr08(p[8+2:]))^wyp2)
	case 12:
		seed = wymum(wyr64x32(p)^seed, wyr32(p[8:])^wyp2)
	case 13:
		seed = wymum(wyr64x32(p)^seed, ((wyr32(p[8:])<<8)|wyr08(p[8+4:]))^wyp2)
	case 14:
		seed = wymum(wyr64x32(p)^seed, ((wyr32(p[8:])<<16)|wyr16(p[8+4:]))^wyp2)
	case 15:
		seed = wymum(wyr64x32(p)^seed, ((wyr32(p[8:])<<24)|(wyr16(p[8+4:])<<8)|wyr08(p[8+6:]))^wyp2)
	case 16:
		seed = wymum(wyr64x32(p)^seed, wyr64x32(p[8:])^wyp2)
	case 17:
		seed = wymum(wyr64x32(p)^seed, wyr64x32(p[8:])^wyp2) ^ wymum(seed, wyr08(p[16:])^wyp3)
	case 18:
		seed = wymum(wyr64x32(p)^seed, wyr64x32(p[8:])^wyp2) ^ wymum(seed, wyr16(p[16:])^wyp3)
	case 19:
		seed = wymum(wyr64x32(p)^seed, wyr64x32(p[8:])^wyp2) ^ wymum(seed, ((wyr16(p[16:])<<8)|wyr08(p[16+2:]))^wyp3)
	case 20:
		seed = wymum(wyr64x32(p)^seed, wyr64x32(p[8:])^wyp2) ^ wymum(seed, wyr32(p[16:])^wyp3)
	case 21:
		seed = wymum(wyr64x32(p)^seed, wyr64x32(p[8:])^wyp2) ^ wymum(seed, ((wyr32(p[16:])<<8)|wyr08(p[16+4:]))^wyp3)
	case 22:
		seed = wymum(wyr64x32(p)^seed, wyr64x32(p[8:])^wyp2) ^ wymum(seed, ((wyr32(p[16:])<<16)|wyr16(p[16+4:]))^wyp3)
	case 23:
		seed = wymum(wyr64x32(p)^seed, wyr64x32(p[8:])^wyp2) ^ wymum(seed, ((wyr32(p[16:])<<24)|(wyr16(p[16+4:])<<8)|wyr08(p[16+6:]))^wyp3)
	case 24:
		seed = wymum(wyr64x32(p)^seed, wyr64x32(p[8:])^wyp2) ^ wymum(seed, wyr64x32(p[16:])^wyp3)
	case 25:
		seed = wymum(wyr64x32(p)^seed, wyr64x32(p[8:])^wyp2) ^ wymum(wyr64x32(p[16:])^seed, wyr08(p[24:])^wyp4)
	case 26:
		seed = wymum(wyr64x32(p)^seed, wyr64x32(p[8:])^wyp2) ^ wymum(wyr64x32(p[16:])^seed, wyr16(p[24:])^wyp4)
	case 27:
		seed = wymum(wyr64x32(p)^seed, wyr64x32(p[8:])^wyp2) ^ wymum(wyr64x32(p[16:])^seed, ((wyr16(p[24:])<<8)|wyr08(p[24+2:]))^wyp4)
	case 28:
		seed = wymum(wyr64x32(p)^seed, wyr64x32(p[8:])^wyp2) ^ wymum(wyr64x32(p[16:])^seed, wyr32(p[24:])^wyp4)
	case 29:
		seed = wymum(wyr64x32(p)^seed, wyr64x32(p[8:])^wyp2) ^ wymum(wyr64x32(p[16:])^seed, ((wyr32(p[24:])<<8)|wyr08(p[24+4:]))^wyp4)
	case 30:
		seed = wymum(wyr64x32(p)^seed, wyr64x32(p[8:])^wyp2) ^ wymum(wyr64x32(p[16:])^seed, ((wyr32(p[24:])<<16)|wyr16(p[24+4:]))^wyp4)
	case 31:
		seed = wymum(wyr64x32(p)^seed, wyr64x32(p[8:])^wyp2) ^ wymum(wyr64x32(p[16:])^seed, ((wyr32(p[24:])<<24)|(wyr16(p[24+4:])<<8)|wyr08(p[24+6:]))^wyp4)
	}
	return wymum(seed, uint64(len(key))^wyp5)
}

type Rng uint64

func (seed *Rng) Next() uint64 {
	*seed += wyp0
	return wymum(uint64(*seed)^wyp1, uint64(*seed))
}
