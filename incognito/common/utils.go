package common

import (
	"encoding/binary"
	"errors"
	"math/big"
	"strconv"
)

// AssertAndConvertStrToNumber asserts and convert a passed input to uint64 number
func AssertAndConvertStrToNumber(numStr interface{}) (uint64, error) {
	assertedNumStr, ok := numStr.(string)
	if !ok {
		return 0, errors.New("Could not assert the passed input to string")
	}
	return strconv.ParseUint(assertedNumStr, 10, 64)
}

// GetShardIDFromLastByte receives a last byte of public key and
// returns a corresponding shardID
func GetShardIDFromLastByte(b byte) byte {
	return byte(int(b) % MaxShardNumber)
}

// AddPaddingBigInt adds padding to big int to it is fixed size
// and returns bytes array
func AddPaddingBigInt(numInt *big.Int, fixedSize int) []byte {
	numBytes := numInt.Bytes()
	lenNumBytes := len(numBytes)
	zeroBytes := make([]byte, fixedSize-lenNumBytes)
	numBytes = append(zeroBytes, numBytes...)
	return numBytes
}

// IntToBytes converts an integer number to 2-byte array in big endian
func IntToBytes(n int) []byte {
	if n == 0 {
		return []byte{0, 0}
	}

	a := big.NewInt(int64(n))

	if len(a.Bytes()) > 2 {
		return []byte{}
	}

	if len(a.Bytes()) == 1 {
		return []byte{0, a.Bytes()[0]}
	}

	return a.Bytes()
}

// BytesToInt reverts an integer number from 2-byte array
func BytesToInt(bytesArr []byte) int {
	if len(bytesArr) != 2 {
		return 0
	}

	numInt := new(big.Int).SetBytes(bytesArr)
	return int(numInt.Int64())
}

// BytesToUint32 converts big endian 4-byte array to uint32 number
func BytesToUint32(b []byte) (uint32, error) {
	if len(b) != Uint32Size {
		return 0, errors.New("invalid length of input BytesToUint32")
	}
	return binary.BigEndian.Uint32(b), nil
}

// Uint32ToBytes converts uint32 number to big endian 4-byte array
func Uint32ToBytes(value uint32) []byte {
	b := make([]byte, Uint32Size)
	binary.BigEndian.PutUint32(b, value)
	return b
}

// BytesToInt32 converts little endian 4-byte array to int32 number
func BytesToInt32(b []byte) (int32, error) {
	if len(b) != Int32Size {
		return 0, errors.New("invalid length of input BytesToInt32")
	}

	return int32(binary.LittleEndian.Uint32(b)), nil
}

// Int32ToBytes converts int32 number to little endian 4-byte array
func Int32ToBytes(value int32) []byte {
	b := make([]byte, Int32Size)
	binary.LittleEndian.PutUint32(b, uint32(value))
	return b
}

// BytesToUint64 converts little endian 8-byte array to uint64 number
func BytesToUint64(b []byte) (uint64, error) {
	if len(b) != Uint64Size {
		return 0, errors.New("invalid length of input BytesToUint64")
	}
	return binary.LittleEndian.Uint64(b), nil
}

// Uint64ToBytes converts uint64 number to little endian 8-byte array
func Uint64ToBytes(value uint64) []byte {
	b := make([]byte, Uint64Size)
	binary.LittleEndian.PutUint64(b, value)
	return b
}