# 加密算法

## 凯撒加密算法

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

## 随机数表加密算法

这种加密算法是在凯撒加密算法上面的升级，我们知道凯撒加密算法主要是对字母表进行移位来加密，但是如何原文中存在高频单词，那么可以通过统计学推断出高频的原文和密文对应关系，
而凯撒加密是通过位移得到的，只要找出其中一个对应关系就可以计算出位移数，这样全文就被破解了，比如：`a -> c` 位移是 2， 那么整个原文通过位移数进行还原即可。
针对这种情况，我们可以构建一张加密算表的来将这种破解的难度增加：设定255个随机的对应加密表。这样即使通过统计学特征推断出其中几个字母，依然无法破解全文。加密算法实现：

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