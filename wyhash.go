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

func wyr3(p []byte, k int) uint64 {
	return (uint64(p[0]) << 16) | (uint64(p[k>>1]) << 8) | uint64(p[k-1])
}

func wyr4(p []byte) uint64 {
	return uint64(binary.LittleEndian.Uint32(p))
}

func wyr8(p []byte) uint64 {
	return uint64(binary.LittleEndian.Uint64(p))
}

func wyr8mix(p []byte) uint64 {
	return uint64(binary.LittleEndian.Uint32(p))<<32 | uint64(binary.LittleEndian.Uint32(p[4:]))
}

func Hash(key []byte, seed uint64) uint64 {
	p := key

	if len(p) == 0 {
		return seed
	}

	switch {
	case len(p) < 4:
		return wymum(wymum(wyr3(p, len(p))^seed^wyp0, seed^wyp1)^seed, uint64(len(p))^wyp4)
	case (len(p) <= 8):
		return wymum(wymum(wyr4(p)^seed^wyp0, wyr4(p[len(p)-4:])^seed^wyp1)^seed, uint64(len(p))^wyp4)
	case (len(p) <= 16):
		return wymum(wymum(wyr8mix(p)^seed^wyp0, wyr8mix(p[len(p)-8:])^seed^wyp1)^seed, uint64(len(p))^wyp4)
	case (len(p) <= 24):
		return wymum(wymum(wyr8mix(p)^seed^wyp0, wyr8mix(p[8:])^seed^wyp1)^wymum(wyr8mix(p[len(key)-8:])^seed^wyp2, seed^wyp3), uint64(len(p))^wyp4)
	case (len(p) <= 32):
		return wymum(wymum(wyr8mix(p)^seed^wyp0, wyr8mix(p[8:])^seed^wyp1)^wymum(wyr8mix(p[16:])^seed^wyp2, wyr8mix(p[len(key)-8:])^seed^wyp3), uint64(len(p))^wyp4)

	}

	see1 := seed
	i := len(p)

	for i > 256 {
		seed = wymum(wyr8(p)^seed^wyp0, wyr8(p[8:])^seed^wyp1) ^ wymum(wyr8(p[16:])^seed^wyp2, wyr8(p[24:])^seed^wyp3)
		see1 = wymum(wyr8(p[32:])^see1^wyp1, wyr8(p[40:])^see1^wyp2) ^ wymum(wyr8(p[48:])^see1^wyp3, wyr8(p[56:])^see1^wyp0)
		seed = wymum(wyr8(p[64:])^seed^wyp0, wyr8(p[72:])^seed^wyp1) ^ wymum(wyr8(p[80:])^seed^wyp2, wyr8(p[88:])^seed^wyp3)
		see1 = wymum(wyr8(p[96:])^see1^wyp1, wyr8(p[104:])^see1^wyp2) ^ wymum(wyr8(p[112:])^see1^wyp3, wyr8(p[120:])^see1^wyp0)
		seed = wymum(wyr8(p[128:])^seed^wyp0, wyr8(p[136:])^seed^wyp1) ^ wymum(wyr8(p[144:])^seed^wyp2, wyr8(p[152:])^seed^wyp3)
		see1 = wymum(wyr8(p[160:])^see1^wyp1, wyr8(p[168:])^see1^wyp2) ^ wymum(wyr8(p[176:])^see1^wyp3, wyr8(p[184:])^see1^wyp0)
		seed = wymum(wyr8(p[192:])^seed^wyp0, wyr8(p[200:])^seed^wyp1) ^ wymum(wyr8(p[208:])^seed^wyp2, wyr8(p[216:])^seed^wyp3)
		see1 = wymum(wyr8(p[224:])^see1^wyp1, wyr8(p[232:])^see1^wyp2) ^ wymum(wyr8(p[240:])^see1^wyp3, wyr8(p[248:])^see1^wyp0)
		i -= 256
		p = p[256:]
	}

	for i > 32 {
		seed = wymum(wyr8(p)^seed^wyp0, wyr8(p[8:])^seed^wyp1)
		see1 = wymum(wyr8(p[16:])^see1^wyp2, wyr8(p[24:])^see1^wyp3)
		i -= 32
		p = p[32:]
	}

	switch {
	case i < 4:
		seed = wymum(wyr3(p, i)^seed^wyp0, seed^wyp1)
	case (i <= 8):
		seed = wymum(wyr4(p)^seed^wyp0, wyr4(p[i-4:])^seed^wyp1)
	case (i <= 16):
		seed = wymum(wyr8mix(p)^seed^wyp0, wyr8mix(p[i-8:])^seed^wyp1)
	case (i <= 24):
		seed = wymum(wyr8mix(p)^seed^wyp0, wyr8mix(p[8:])^seed^wyp1)
		see1 = wymum(wyr8mix(p[i-8:])^see1^wyp2, see1^wyp3)
	default:
		seed = wymum(wyr8mix(p)^seed^wyp0, wyr8mix(p[8:])^seed^wyp1)
		see1 = wymum(wyr8mix(p[16:])^see1^wyp2, wyr8mix(p[i-8:])^see1^wyp3)

	}

	return wymum(seed^see1, uint64(len(key))^wyp4)
}

type Rng uint64

func (seed *Rng) Next() uint64 {
	*seed += wyp0
	return wymum(uint64(*seed)^wyp1, uint64(*seed))
}
