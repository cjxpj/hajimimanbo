package main

import (
	"fmt"
	"strings"
	"testing"
)

// -------------------- 测试 --------------------
func TestDebug(t *testing.T) {
	token := "test"
	text := "ok"
	// 重复文本
	text = strings.Repeat(text, 2)
	if enc, err := Encrypt(text, token); err == nil {
		// fmt.Println("加密前:", text)
		fmt.Println("加密后:", enc)
		if dec, err := Decrypt(enc, token); err == nil {
			fmt.Println("解密后:", dec)
		}
	}
}
