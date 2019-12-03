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

func wyr3(p []byte) uint64 {
	k := len(p)
	return (uint64(p[0]) << 16) | (uint64(p[k>>1]) << 8) | uint64(p[k-1])
}

func wyr8mix(p []byte) uint64 {
	return uint64(binary.LittleEndian.Uint32(p[:4]))<<32 | uint64(binary.LittleEndian.Uint32(p[4:8]))
}

func Hash(key []byte, seed uint64) uint64 {
	p := key

	if len(p) == 0 {
		return seed
	}

	switch {
	case len(p) < 4:
		return wymum(wymum(wyr3(p)^seed^wyp0, seed^wyp1)^seed, uint64(len(p))^wyp4)
	case len(p) <= 8:
		return wymum(wymum(uint64(binary.LittleEndian.Uint32(p[:4]))^seed^wyp0, uint64(binary.LittleEndian.Uint32(p[len(p)-4:len(p)-4+4]))^seed^wyp1)^seed, uint64(len(p))^wyp4)
	case len(p) <= 16:
		return wymum(wymum(wyr8mix(p)^seed^wyp0, wyr8mix(p[len(p)-8:])^seed^wyp1)^seed, uint64(len(p))^wyp4)
	case len(p) <= 24:
		return wymum(wymum(wyr8mix(p)^seed^wyp0, wyr8mix(p[8:])^seed^wyp1)^wymum(wyr8mix(p[len(key)-8:])^seed^wyp2, seed^wyp3), uint64(len(p))^wyp4)
	case len(p) <= 32:
		return wymum(wymum(wyr8mix(p)^seed^wyp0, wyr8mix(p[8:])^seed^wyp1)^wymum(wyr8mix(p[16:])^seed^wyp2, wyr8mix(p[len(key)-8:])^seed^wyp3), uint64(len(p))^wyp4)

	}

	see1 := seed

	for len(p) > 256 {
		seed = wymum(binary.LittleEndian.Uint64(p[:8])^seed^wyp0, binary.LittleEndian.Uint64(p[8:8+8])^seed^wyp1) ^ wymum(binary.LittleEndian.Uint64(p[16:16+8])^seed^wyp2, binary.LittleEndian.Uint64(p[24:24+8])^seed^wyp3)
		see1 = wymum(binary.LittleEndian.Uint64(p[32:32+8])^see1^wyp1, binary.LittleEndian.Uint64(p[40:40+8])^see1^wyp2) ^ wymum(binary.LittleEndian.Uint64(p[48:48+8])^see1^wyp3, binary.LittleEndian.Uint64(p[56:56+8])^see1^wyp0)
		seed = wymum(binary.LittleEndian.Uint64(p[64:64+8])^seed^wyp0, binary.LittleEndian.Uint64(p[72:72+8])^seed^wyp1) ^ wymum(binary.LittleEndian.Uint64(p[80:80+8])^seed^wyp2, binary.LittleEndian.Uint64(p[88:88+8])^seed^wyp3)
		see1 = wymum(binary.LittleEndian.Uint64(p[96:96+8])^see1^wyp1, binary.LittleEndian.Uint64(p[104:104+8])^see1^wyp2) ^ wymum(binary.LittleEndian.Uint64(p[112:112+8])^see1^wyp3, binary.LittleEndian.Uint64(p[120:120+8])^see1^wyp0)
		seed = wymum(binary.LittleEndian.Uint64(p[128:128+8])^seed^wyp0, binary.LittleEndian.Uint64(p[136:136+8])^seed^wyp1) ^ wymum(binary.LittleEndian.Uint64(p[144:144+8])^seed^wyp2, binary.LittleEndian.Uint64(p[152:152+8])^seed^wyp3)
		see1 = wymum(binary.LittleEndian.Uint64(p[160:160+8])^see1^wyp1, binary.LittleEndian.Uint64(p[168:168+8])^see1^wyp2) ^ wymum(binary.LittleEndian.Uint64(p[176:176+8])^see1^wyp3, binary.LittleEndian.Uint64(p[184:184+8])^see1^wyp0)
		seed = wymum(binary.LittleEndian.Uint64(p[192:192+8])^seed^wyp0, binary.LittleEndian.Uint64(p[200:200+8])^seed^wyp1) ^ wymum(binary.LittleEndian.Uint64(p[208:208+8])^seed^wyp2, binary.LittleEndian.Uint64(p[216:216+8])^seed^wyp3)
		see1 = wymum(binary.LittleEndian.Uint64(p[224:224+8])^see1^wyp1, binary.LittleEndian.Uint64(p[232:232+8])^see1^wyp2) ^ wymum(binary.LittleEndian.Uint64(p[240:240+8])^see1^wyp3, binary.LittleEndian.Uint64(p[248:248+8])^see1^wyp0)
		p = p[256:]
	}

	for len(p) > 32 {
		seed = wymum(binary.LittleEndian.Uint64(p[:8])^seed^wyp0, binary.LittleEndian.Uint64(p[8:8+8])^seed^wyp1)
		see1 = wymum(binary.LittleEndian.Uint64(p[16:16+8])^see1^wyp2, binary.LittleEndian.Uint64(p[24:24+8])^see1^wyp3)
		p = p[32:]
	}

	switch {
	case len(p) < 4:
		seed = wymum(wyr3(p)^seed^wyp0, seed^wyp1)
	case len(p) <= 8:
		seed = wymum(uint64(binary.LittleEndian.Uint32(p[:4]))^seed^wyp0, uint64(binary.LittleEndian.Uint32(p[len(p)-4:len(p)-4+4]))^seed^wyp1)
	case len(p) <= 16:
		seed = wymum(wyr8mix(p)^seed^wyp0, wyr8mix(p[len(p)-8:])^seed^wyp1)
	case len(p) <= 24:
		seed = wymum(wyr8mix(p)^seed^wyp0, wyr8mix(p[8:])^seed^wyp1)
		see1 = wymum(wyr8mix(p[len(p)-8:])^see1^wyp2, see1^wyp3)
	default:
		seed = wymum(wyr8mix(p)^seed^wyp0, wyr8mix(p[8:])^seed^wyp1)
		see1 = wymum(wyr8mix(p[16:])^see1^wyp2, wyr8mix(p[len(p)-8:])^see1^wyp3)

	}

	return wymum(seed^see1, uint64(len(key))^wyp4)
}

type Rng uint64

func (seed *Rng) Next() uint64 {
	*seed += wyp0
	return wymum(uint64(*seed)^wyp1, uint64(*seed))
}
