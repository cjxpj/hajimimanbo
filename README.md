# HaJiMiManbo LZ77 加密库

一个基于 **LZ77 压缩 + ChaCha20-Poly1305 加密** 的 Go 库，并用“哈基米曼波”字符进行文本表示。  
适合对文本进行压缩和安全加密，同时输出为可读字符形式。

---

## 特性

- LZ77 压缩重复数据
- ChaCha20-Poly1305 对称加密
- 哈基米曼波字符编码（可打印文本形式）
- 提供简单的 `Encrypt` / `Decrypt` 函数

---

## 安装

直接在你的项目中引入即可，无需额外依赖（Go Modules 已包含所需加密包）：

```bash
go get github.com/cjxpj/hajimimanbo
