# 流量混淆算法

> 安全声明：当前 `simple` / `random` 仅是字节替换和线性同余生成表的混淆层，不是现代密码学安全通道，不能提供机密性、完整性或重放防护。

## simple: 凯撒位移混淆

这里使用了最简单的凯撒位移(Caesar cipher)做流量混淆，即将字节表整体做固定偏移。
这种方式实现简单、速度快，但非常容易被还原，只适合低门槛的协议伪装，不能当作安全加密。

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

## random: 替换表混淆

`random` 在 `simple` 的基础上换成一张由密码派生的替换表，用来提高直接观察字节模式时的混淆程度。
它仍然不是现代密码学算法，无法防御主动探测、已知明文、重放或篡改攻击。适用场景仍然只是“轻量混淆”，不是“安全传输”。

```
func CreateRandomCipher(passwd string) (*DefaultAuth, error){
	var s *DefaultAuth
	// 采用随机编码表进行加密
	sumint := 0
	if len(passwd) == 0 {
		return nil, errors.New("密码不能为空")
	}
	for v := range passwd {
		sumint += int(v)
	}
	var encodeString [256]byte
	var decodeString [256]byte
	// 创建随机数 (a*x + b) mod m 
	for i := 0; i < 256; i++{
		encodeString[i] = byte((RANDOM_A*sumint+RANDOM_B)%RANDOM_M)
		decodeString[(RANDOM_A*sumint+RANDOM_B)%RANDOM_M] = byte(i)
		sumint = (RANDOM_A*sumint+RANDOM_B)%RANDOM_M
	}
	s = &DefaultAuth{
		Encode: &encodeString,
		Decode: &decodeString,
	}
	return s, nil
}
```
