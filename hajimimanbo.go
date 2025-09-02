package hajimimanbo

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"math/big"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// -------------------- 常量 --------------------
const (
	magic        = "HJM1"
	saltSize     = 16
	nonceSize    = 12
	keySize      = 32
	lzWindowSize = 1024
)

var symbols = []rune{'哈', '基', '米', '曼', '波'}
var symbolMap = map[rune]int{
	'哈': 0, '基': 1, '米': 2, '曼': 3, '波': 4,
}

func toHajimiString(data []byte) string {
	n := new(big.Int).SetBytes(data)
	base := big.NewInt(5)
	var out []rune
	zero := big.NewInt(0)
	for n.Cmp(zero) > 0 {
		mod := new(big.Int)
		n.DivMod(n, base, mod)
		out = append([]rune{symbols[mod.Int64()]}, out...)
	}
	return string(out)
}

func fromHajimiString(s string) ([]byte, error) {
	n := big.NewInt(0)
	base := big.NewInt(5)
	for _, r := range s {
		v, ok := symbolMap[r]
		if !ok {
			return nil, errors.New("非法字符")
		}
		n.Mul(n, base)
		n.Add(n, big.NewInt(int64(v)))
	}
	return n.Bytes(), nil
}

// -------------------- LZ77 --------------------
type Triple struct {
	Offset int
	Length int
	Next   byte
}

func compressLZ77(input string) []Triple {
	data := []byte(input)
	var result []Triple
	for i := 0; i < len(data); {
		bestOffset, bestLength := 0, 0
		start := i - lzWindowSize
		if start < 0 {
			start = 0
		}
		for j := start; j < i; j++ {
			length := 0
			for i+length < len(data) && data[j+length] == data[i+length] {
				length++
			}
			if length > bestLength {
				bestLength = length
				bestOffset = i - j
			}
		}
		next := byte(0)
		if i+bestLength < len(data) {
			next = data[i+bestLength]
		}
		result = append(result, Triple{bestOffset, bestLength, next})
		i += bestLength + 1
	}
	return result
}

func decompressLZ77(triples []Triple) string {
	data := make([]byte, 0, 1024)
	for _, t := range triples {
		start := len(data) - t.Offset
		for i := 0; i < t.Length; i++ {
			data = append(data, data[start+i])
		}
		if t.Next != 0 {
			data = append(data, t.Next)
		}
	}
	return string(data)
}

// 使用 2 字节存 Offset/Length
func triplesToBytes(triples []Triple) []byte {
	buf := new(bytes.Buffer)
	for _, t := range triples {
		buf.WriteByte(byte(t.Offset >> 8))
		buf.WriteByte(byte(t.Offset & 0xFF))
		buf.WriteByte(byte(t.Length >> 8))
		buf.WriteByte(byte(t.Length & 0xFF))
		buf.WriteByte(t.Next)
	}
	return buf.Bytes()
}

func bytesToTriples(data []byte) []Triple {
	var triples []Triple
	for i := 0; i+4 < len(data); i += 5 {
		offset := int(data[i])<<8 | int(data[i+1])
		length := int(data[i+2])<<8 | int(data[i+3])
		triples = append(triples, Triple{
			Offset: offset,
			Length: length,
			Next:   data[i+4],
		})
	}
	return triples
}

// -------------------- 公开 --------------------

/*
 * 加密
 * @param plainText 明文
 * @param token 密钥
 * @return 加密后的密文
 */
func Encrypt(plainText, token string) (string, error) {
	triples := compressLZ77(plainText)
	compressed := triplesToBytes(triples)

	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}

	key := make([]byte, keySize)
	hkdf := hkdf.New(sha256.New, []byte(token), salt, []byte("HaJiMiManbo"))
	if _, err := io.ReadFull(hkdf, key); err != nil {
		return "", err
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aead.Seal(nil, nonce, compressed, nil)

	var buf bytes.Buffer
	buf.WriteString(magic)
	buf.Write(salt)
	buf.Write(nonce)
	buf.Write(ciphertext)

	return toHajimiString(buf.Bytes()), nil
}

/*
 * 解密
 * @param data 密文
 * @param token 密钥
 * @return 解密后的明文
 */
func Decrypt(data, token string) (string, error) {
	raw, err := fromHajimiString(data)
	if err != nil {
		return "", err
	}
	if len(raw) < 4+saltSize+nonceSize {
		return "", errors.New("数据格式错误")
	}
	if string(raw[:4]) != magic {
		return "", errors.New("魔术头不匹配")
	}
	off := 4
	salt := raw[off : off+saltSize]
	off += saltSize
	nonce := raw[off : off+nonceSize]
	off += nonceSize
	ciphertext := raw[off:]

	key := make([]byte, keySize)
	hkdf := hkdf.New(sha256.New, []byte(token), salt, []byte("HaJiMiManbo"))
	if _, err := io.ReadFull(hkdf, key); err != nil {
		return "", err
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return "", err
	}

	compressed, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", errors.New("解密失败")
	}

	triples := bytesToTriples(compressed)
	return decompressLZ77(triples), nil
}
