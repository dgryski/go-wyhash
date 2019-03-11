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

func Hash(key []byte, seed uint64) uint64 {
	ptr := key

	for len(ptr) >= 32 {
		seed = wyhashmix(seed^wyhashp1, binary.LittleEndian.Uint64(ptr[:8])) ^ wyhashmix(seed^wyhashp2, binary.LittleEndian.Uint64(ptr[8:16])) ^ wyhashmix(seed^wyhashp3, binary.LittleEndian.Uint64(ptr[16:24])) ^ wyhashmix(seed^wyhashp4, binary.LittleEndian.Uint64(ptr[24:32]))
		ptr = ptr[32:]
	}

	switch len(ptr) {
	case 1:
		seed = wyhashmix(seed^wyhashp1, uint64(ptr[0]))
	case 2:
		seed = wyhashmix(seed^wyhashp1, uint64(binary.LittleEndian.Uint16(ptr)))
	case 3:
		seed = wyhashmix(seed^wyhashp1, (uint64(binary.LittleEndian.Uint16(ptr))<<8)|uint64(ptr[2]))
	case 4:
		seed = wyhashmix(seed^wyhashp1, uint64(binary.LittleEndian.Uint32(ptr)))
	case 5:
		seed = wyhashmix(seed^wyhashp1, (uint64(binary.LittleEndian.Uint32(ptr))<<8)|uint64(ptr[4]))
	case 6:
		seed = wyhashmix(seed^wyhashp1, (uint64(binary.LittleEndian.Uint32(ptr[:4]))<<16)|uint64(binary.LittleEndian.Uint16(ptr[4:6])))
	case 7:
		seed = wyhashmix(seed^wyhashp1, (uint64(binary.LittleEndian.Uint32(ptr[:4]))<<24)|(uint64(binary.LittleEndian.Uint16(ptr[4:6]))<<8)|uint64(ptr[6]))
	case 8:
		seed = wyhashmix(seed^wyhashp1, binary.LittleEndian.Uint64(ptr))
	case 9:
		seed = wyhashmix(seed^wyhashp1, binary.LittleEndian.Uint64(ptr)) ^ wyhashmix(seed^wyhashp2, uint64(ptr[8]))
	case 10:
		seed = wyhashmix(seed^wyhashp1, binary.LittleEndian.Uint64(ptr)) ^ wyhashmix(seed^wyhashp2, uint64(binary.LittleEndian.Uint16(ptr[8:10])))
	case 11:
		seed = wyhashmix(seed^wyhashp1, binary.LittleEndian.Uint64(ptr)) ^ wyhashmix(seed^wyhashp2, (uint64(binary.LittleEndian.Uint16(ptr[8:10]))<<8)|uint64(ptr[8+2]))
	case 12:
		seed = wyhashmix(seed^wyhashp1, binary.LittleEndian.Uint64(ptr)) ^ wyhashmix(seed^wyhashp2, uint64(binary.LittleEndian.Uint32(ptr[8:12])))
	case 13:
		seed = wyhashmix(seed^wyhashp1, binary.LittleEndian.Uint64(ptr)) ^ wyhashmix(seed^wyhashp2, (uint64(binary.LittleEndian.Uint32(ptr[8:12]))<<8)|uint64(ptr[8+4]))
	case 14:
		seed = wyhashmix(seed^wyhashp1, binary.LittleEndian.Uint64(ptr)) ^ wyhashmix(seed^wyhashp2, (uint64(binary.LittleEndian.Uint32(ptr[8:12]))<<16)|uint64(binary.LittleEndian.Uint16(ptr[12:14])))
	case 15:
		seed = wyhashmix(seed^wyhashp1, binary.LittleEndian.Uint64(ptr)) ^ wyhashmix(seed^wyhashp2, (uint64(binary.LittleEndian.Uint32(ptr[8:12]))<<24)|(uint64(binary.LittleEndian.Uint16(ptr[12:14]))<<8)|uint64(ptr[8+6]))
	case 16:
		seed = wyhashmix(seed^wyhashp1, binary.LittleEndian.Uint64(ptr)) ^ wyhashmix(seed^wyhashp2, binary.LittleEndian.Uint64(ptr[8:16]))
	case 17:
		seed = wyhashmix(seed^wyhashp1, binary.LittleEndian.Uint64(ptr)) ^ wyhashmix(seed^wyhashp2, binary.LittleEndian.Uint64(ptr[8:16])) ^ wyhashmix(seed^wyhashp3, uint64(ptr[16]))
	case 18:
		seed = wyhashmix(seed^wyhashp1, binary.LittleEndian.Uint64(ptr)) ^ wyhashmix(seed^wyhashp2, binary.LittleEndian.Uint64(ptr[8:16])) ^ wyhashmix(seed^wyhashp3, uint64(binary.LittleEndian.Uint16(ptr[16:18])))
	case 19:
		seed = wyhashmix(seed^wyhashp1, binary.LittleEndian.Uint64(ptr)) ^ wyhashmix(seed^wyhashp2, binary.LittleEndian.Uint64(ptr[8:16])) ^ wyhashmix(seed^wyhashp3, (uint64(binary.LittleEndian.Uint16(ptr[16:18]))<<8)|uint64(ptr[18]))
	case 20:
		seed = wyhashmix(seed^wyhashp1, binary.LittleEndian.Uint64(ptr)) ^ wyhashmix(seed^wyhashp2, binary.LittleEndian.Uint64(ptr[8:16])) ^ wyhashmix(seed^wyhashp3, uint64(binary.LittleEndian.Uint32(ptr[16:20])))
	case 21:
		seed = wyhashmix(seed^wyhashp1, binary.LittleEndian.Uint64(ptr)) ^ wyhashmix(seed^wyhashp2, binary.LittleEndian.Uint64(ptr[8:16])) ^ wyhashmix(seed^wyhashp3, (uint64(binary.LittleEndian.Uint32(ptr[16:20]))<<8)|uint64(ptr[16+4]))
	case 22:
		seed = wyhashmix(seed^wyhashp1, binary.LittleEndian.Uint64(ptr)) ^ wyhashmix(seed^wyhashp2, binary.LittleEndian.Uint64(ptr[8:16])) ^ wyhashmix(seed^wyhashp3, (uint64(binary.LittleEndian.Uint32(ptr[16:20]))<<16)|uint64(binary.LittleEndian.Uint16(ptr[20:22])))
	case 23:
		seed = wyhashmix(seed^wyhashp1, binary.LittleEndian.Uint64(ptr)) ^ wyhashmix(seed^wyhashp2, binary.LittleEndian.Uint64(ptr[8:16])) ^ wyhashmix(seed^wyhashp3, (uint64(binary.LittleEndian.Uint32(ptr[16:20]))<<24)|(uint64(binary.LittleEndian.Uint16(ptr[20:22]))<<8)|uint64(ptr[22]))
	case 24:
		seed = wyhashmix(seed^wyhashp1, binary.LittleEndian.Uint64(ptr)) ^ wyhashmix(seed^wyhashp2, binary.LittleEndian.Uint64(ptr[8:16])) ^ wyhashmix(seed^wyhashp3, binary.LittleEndian.Uint64(ptr[16:24]))
	case 25:
		seed = wyhashmix(seed^wyhashp1, binary.LittleEndian.Uint64(ptr)) ^ wyhashmix(seed^wyhashp2, binary.LittleEndian.Uint64(ptr[8:16])) ^ wyhashmix(seed^wyhashp3, binary.LittleEndian.Uint64(ptr[16:24])) ^ wyhashmix(seed^wyhashp4, uint64(ptr[24]))
	case 26:
		seed = wyhashmix(seed^wyhashp1, binary.LittleEndian.Uint64(ptr)) ^ wyhashmix(seed^wyhashp2, binary.LittleEndian.Uint64(ptr[8:16])) ^ wyhashmix(seed^wyhashp3, binary.LittleEndian.Uint64(ptr[16:24])) ^ wyhashmix(seed^wyhashp4, uint64(binary.LittleEndian.Uint16(ptr[24:26])))
	case 27:
		seed = wyhashmix(seed^wyhashp1, binary.LittleEndian.Uint64(ptr)) ^ wyhashmix(seed^wyhashp2, binary.LittleEndian.Uint64(ptr[8:16])) ^ wyhashmix(seed^wyhashp3, binary.LittleEndian.Uint64(ptr[16:24])) ^ wyhashmix(seed^wyhashp4, (uint64(binary.LittleEndian.Uint16(ptr[24:26]))<<8)|uint64(ptr[26]))
	case 28:
		seed = wyhashmix(seed^wyhashp1, binary.LittleEndian.Uint64(ptr)) ^ wyhashmix(seed^wyhashp2, binary.LittleEndian.Uint64(ptr[8:16])) ^ wyhashmix(seed^wyhashp3, binary.LittleEndian.Uint64(ptr[16:24])) ^ wyhashmix(seed^wyhashp4, uint64(binary.LittleEndian.Uint32(ptr[24:28])))
	case 29:
		seed = wyhashmix(seed^wyhashp1, binary.LittleEndian.Uint64(ptr)) ^ wyhashmix(seed^wyhashp2, binary.LittleEndian.Uint64(ptr[8:16])) ^ wyhashmix(seed^wyhashp3, binary.LittleEndian.Uint64(ptr[16:24])) ^ wyhashmix(seed^wyhashp4, (uint64(binary.LittleEndian.Uint32(ptr[24:28]))<<8)|uint64(ptr[28]))
	case 30:
		seed = wyhashmix(seed^wyhashp1, binary.LittleEndian.Uint64(ptr)) ^ wyhashmix(seed^wyhashp2, binary.LittleEndian.Uint64(ptr[8:16])) ^ wyhashmix(seed^wyhashp3, binary.LittleEndian.Uint64(ptr[16:24])) ^ wyhashmix(seed^wyhashp4, (uint64(binary.LittleEndian.Uint32(ptr[24:28]))<<16)|uint64(binary.LittleEndian.Uint16(ptr[28:30])))
	case 31:
		seed = wyhashmix(seed^wyhashp1, binary.LittleEndian.Uint64(ptr)) ^ wyhashmix(seed^wyhashp2, binary.LittleEndian.Uint64(ptr[8:16])) ^ wyhashmix(seed^wyhashp3, binary.LittleEndian.Uint64(ptr[16:24])) ^ wyhashmix(seed^wyhashp4, (uint64(binary.LittleEndian.Uint32(ptr[24:28]))<<24)|(uint64(binary.LittleEndian.Uint16(ptr[28:30]))<<8)|uint64(ptr[30]))
	}
	return wyhashmix(seed, uint64(len(key)))
}

type Rng uint64

func (seed *Rng) Next() uint64 {
	*seed += wyhashp0
	return wyrngmix(wyrngmix(uint64(*seed), wyhashp1), wyhashp2)

}

func wyrngmix(A, B uint64) uint64 {
	hi, lo := bits.Mul64(A, B)
	return hi ^ lo
}
