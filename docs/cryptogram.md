# 加密算法

这里使用了最简单的加密算法，凯撒加密(Caesar cipher)，即明文中的所有字母都在字母表上向后（或向前）按照一个固定数目进行偏移后被替换成密文。
因为该算法非常容易实现，而且简单快速，因此被选择为这个工具的加密算法。

```
func CreateAuth(passwd string) *socks5Auth{
	// 采用最简单的凯撒位移法
	sumint := 0
	for v := range passwd {
		sumint += int(v)
	}
	sumint = sumint % 256
	var encodeString [256]byte
	var decodeString [256]byte
	for i := 0; i < 256; i++{
		encodeString[i] = byte((i+sumint)%256)
		decodeString[i] = byte((i-sumint+256)%256)
	}
	return &socks5Auth{
		KeyMoved: sumint,
		Encode: &encodeString,
		Decode: &decodeString,
	}
}
```