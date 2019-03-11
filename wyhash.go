package wyhash

import (
	"encoding/binary"
	"math/bits"
)

const (
	wyhashp0 = 0x60bee2bee120fc15
	wyhashp1 = 0xa3b195354a39b70d
	wyhashp2 = 0x1b03738712fad5c9
	wyhashp3 = 0xd985068bc5439bd7
	wyhashp4 = 0x897f236fb004a8e7
)

func wyhashmix(A, B uint64) uint64 {
	hi, lo := bits.Mul64(A, B^wyhashp0)
	return hi ^ lo
}

func wyhashread64(ptr []byte) uint64 { return binary.LittleEndian.Uint64(ptr[:8]) }
func wyhashread32(ptr []byte) uint64 { return uint64(binary.LittleEndian.Uint32(ptr[:4])) }
func wyhashread16(ptr []byte) uint64 { return uint64(binary.LittleEndian.Uint16(ptr[:2])) }
func wyhashread08(ptr []byte) uint64 { return uint64(ptr[0]) }

func Hash(key []byte, seed uint64) uint64 {
	ptr := key

	for len(ptr) >= 32 {
		seed = wyhashmix(seed^wyhashp1, wyhashread64(ptr[:8])) ^ wyhashmix(seed^wyhashp2, wyhashread64(ptr[8:16])) ^ wyhashmix(seed^wyhashp3, wyhashread64(ptr[16:24])) ^ wyhashmix(seed^wyhashp4, wyhashread64(ptr[24:32]))
		ptr = ptr[32:]
	}

	switch len(ptr) {
	case 1:
		seed = wyhashmix(seed^wyhashp1, wyhashread08(ptr))
	case 2:
		seed = wyhashmix(seed^wyhashp1, wyhashread16(ptr))
	case 3:
		seed = wyhashmix(seed^wyhashp1, (wyhashread16(ptr)<<8)|wyhashread08(ptr[2:]))
	case 4:
		seed = wyhashmix(seed^wyhashp1, wyhashread32(ptr))
	case 5:
		seed = wyhashmix(seed^wyhashp1, (wyhashread32(ptr)<<8)|wyhashread08(ptr[4:]))
	case 6:
		seed = wyhashmix(seed^wyhashp1, (wyhashread32(ptr)<<16)|wyhashread16(ptr[4:]))
	case 7:
		seed = wyhashmix(seed^wyhashp1, (wyhashread32(ptr)<<24)|(wyhashread16(ptr[4:])<<8)|wyhashread08(ptr[6:]))
	case 8:
		seed = wyhashmix(seed^wyhashp1, wyhashread64(ptr))
	case 9:
		seed = wyhashmix(seed^wyhashp1, wyhashread64(ptr)) ^ wyhashmix(seed^wyhashp2, wyhashread08(ptr[8:]))
	case 10:
		seed = wyhashmix(seed^wyhashp1, wyhashread64(ptr)) ^ wyhashmix(seed^wyhashp2, wyhashread16(ptr[8:]))
	case 11:
		seed = wyhashmix(seed^wyhashp1, wyhashread64(ptr)) ^ wyhashmix(seed^wyhashp2, (wyhashread16(ptr[8:])<<8)|wyhashread08(ptr[8+2:]))
	case 12:
		seed = wyhashmix(seed^wyhashp1, wyhashread64(ptr)) ^ wyhashmix(seed^wyhashp2, wyhashread32(ptr[8:]))
	case 13:
		seed = wyhashmix(seed^wyhashp1, wyhashread64(ptr)) ^ wyhashmix(seed^wyhashp2, (wyhashread32(ptr[8:])<<8)|wyhashread08(ptr[8+4:]))
	case 14:
		seed = wyhashmix(seed^wyhashp1, wyhashread64(ptr)) ^ wyhashmix(seed^wyhashp2, (wyhashread32(ptr[8:])<<16)|wyhashread16(ptr[8+4:]))
	case 15:
		seed = wyhashmix(seed^wyhashp1, wyhashread64(ptr)) ^ wyhashmix(seed^wyhashp2, (wyhashread32(ptr[8:])<<24)|(wyhashread16(ptr[8+4:])<<8)|wyhashread08(ptr[8+6:]))
	case 16:
		seed = wyhashmix(seed^wyhashp1, wyhashread64(ptr)) ^ wyhashmix(seed^wyhashp2, wyhashread64(ptr[8:]))
	case 17:
		seed = wyhashmix(seed^wyhashp1, wyhashread64(ptr)) ^ wyhashmix(seed^wyhashp2, wyhashread64(ptr[8:])) ^ wyhashmix(seed^wyhashp3, wyhashread08(ptr[16:]))
	case 18:
		seed = wyhashmix(seed^wyhashp1, wyhashread64(ptr)) ^ wyhashmix(seed^wyhashp2, wyhashread64(ptr[8:])) ^ wyhashmix(seed^wyhashp3, wyhashread16(ptr[16:]))
	case 19:
		seed = wyhashmix(seed^wyhashp1, wyhashread64(ptr)) ^ wyhashmix(seed^wyhashp2, wyhashread64(ptr[8:])) ^ wyhashmix(seed^wyhashp3, (wyhashread16(ptr[16:])<<8)|wyhashread08(ptr[16+2:]))
	case 20:
		seed = wyhashmix(seed^wyhashp1, wyhashread64(ptr)) ^ wyhashmix(seed^wyhashp2, wyhashread64(ptr[8:])) ^ wyhashmix(seed^wyhashp3, wyhashread32(ptr[16:]))
	case 21:
		seed = wyhashmix(seed^wyhashp1, wyhashread64(ptr)) ^ wyhashmix(seed^wyhashp2, wyhashread64(ptr[8:])) ^ wyhashmix(seed^wyhashp3, (wyhashread32(ptr[16:])<<8)|wyhashread08(ptr[16+4:]))
	case 22:
		seed = wyhashmix(seed^wyhashp1, wyhashread64(ptr)) ^ wyhashmix(seed^wyhashp2, wyhashread64(ptr[8:])) ^ wyhashmix(seed^wyhashp3, (wyhashread32(ptr[16:])<<16)|wyhashread16(ptr[16+4:]))
	case 23:
		seed = wyhashmix(seed^wyhashp1, wyhashread64(ptr)) ^ wyhashmix(seed^wyhashp2, wyhashread64(ptr[8:])) ^ wyhashmix(seed^wyhashp3, (wyhashread32(ptr[16:])<<24)|(wyhashread16(ptr[16+4:])<<8)|wyhashread08(ptr[16+6:]))
	case 24:
		seed = wyhashmix(seed^wyhashp1, wyhashread64(ptr)) ^ wyhashmix(seed^wyhashp2, wyhashread64(ptr[8:])) ^ wyhashmix(seed^wyhashp3, wyhashread64(ptr[16:]))
	case 25:
		seed = wyhashmix(seed^wyhashp1, wyhashread64(ptr)) ^ wyhashmix(seed^wyhashp2, wyhashread64(ptr[8:])) ^ wyhashmix(seed^wyhashp3, wyhashread64(ptr[16:])) ^ wyhashmix(seed^wyhashp4, wyhashread08(ptr[24:]))
	case 26:
		seed = wyhashmix(seed^wyhashp1, wyhashread64(ptr)) ^ wyhashmix(seed^wyhashp2, wyhashread64(ptr[8:])) ^ wyhashmix(seed^wyhashp3, wyhashread64(ptr[16:])) ^ wyhashmix(seed^wyhashp4, wyhashread16(ptr[24:]))
	case 27:
		seed = wyhashmix(seed^wyhashp1, wyhashread64(ptr)) ^ wyhashmix(seed^wyhashp2, wyhashread64(ptr[8:])) ^ wyhashmix(seed^wyhashp3, wyhashread64(ptr[16:])) ^ wyhashmix(seed^wyhashp4, (wyhashread16(ptr[24:])<<8)|wyhashread08(ptr[24+2:]))
	case 28:
		seed = wyhashmix(seed^wyhashp1, wyhashread64(ptr)) ^ wyhashmix(seed^wyhashp2, wyhashread64(ptr[8:])) ^ wyhashmix(seed^wyhashp3, wyhashread64(ptr[16:])) ^ wyhashmix(seed^wyhashp4, wyhashread32(ptr[24:]))
	case 29:
		seed = wyhashmix(seed^wyhashp1, wyhashread64(ptr)) ^ wyhashmix(seed^wyhashp2, wyhashread64(ptr[8:])) ^ wyhashmix(seed^wyhashp3, wyhashread64(ptr[16:])) ^ wyhashmix(seed^wyhashp4, (wyhashread32(ptr[24:])<<8)|wyhashread08(ptr[24+4:]))
	case 30:
		seed = wyhashmix(seed^wyhashp1, wyhashread64(ptr)) ^ wyhashmix(seed^wyhashp2, wyhashread64(ptr[8:])) ^ wyhashmix(seed^wyhashp3, wyhashread64(ptr[16:])) ^ wyhashmix(seed^wyhashp4, (wyhashread32(ptr[24:])<<16)|wyhashread16(ptr[24+4:]))
	case 31:
		seed = wyhashmix(seed^wyhashp1, wyhashread64(ptr)) ^ wyhashmix(seed^wyhashp2, wyhashread64(ptr[8:])) ^ wyhashmix(seed^wyhashp3, wyhashread64(ptr[16:])) ^ wyhashmix(seed^wyhashp4, (wyhashread32(ptr[24:])<<24)|(wyhashread16(ptr[24+4:])<<8)|wyhashread08(ptr[24+6:]))
	}
	return wyhashmix(seed, uint64(len(key)))
}

type Rng uint64

func (seed *Rng) Next() uint64 {
	*seed += wyhashp0
	return wyrngmix(wyrngmix(uint64(*seed), wyhashp1), wyhashp2)

}

func wyrngmix(A, B uint64) uint64 {
	hi, lo := bits.Mul64(A, B^wyhashp0)
	return hi ^ lo
}
