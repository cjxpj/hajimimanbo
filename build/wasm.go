//go:build js && wasm

package main

import (
	"syscall/js"

	"github.com/cjxpj/hajimimanbo"
)

func main() {
	js.Global().Set("encrypt", js.FuncOf(encrypt))
	js.Global().Set("decrypt", js.FuncOf(decrypt))

	select {}
}

func encrypt(this js.Value, args []js.Value) any {
	if len(args) != 2 {
		return jsErr("所需参数(密钥, 文本)")
	}
	key := args[0].String()
	text := args[1].String()
	out, err := hajimimanbo.Encrypt(text, key)
	if err != nil {
		return jsErr(err.Error())
	}
	return js.ValueOf(out)
}

func decrypt(this js.Value, args []js.Value) any {
	if len(args) != 2 {
		return jsErr("所需参数(密钥, 文本)")
	}
	key := args[0].String()
	text := args[1].String()
	out, err := hajimimanbo.Decrypt(text, key)
	if err != nil {
		return jsErr(err.Error())
	}
	return js.ValueOf(out)
}

func jsErr(msg string) js.Value {
	return js.Global().Get("Error").New(msg)
}
