package anytls

import (
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

const CheckMark = -1

var defaultPaddingScheme = []byte(`stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000`)

// paddingScheme 存储 padding 配置（采用官方简洁风格）
type paddingScheme struct {
	rawScheme []byte            // 原始 scheme 字符串
	scheme    map[string]string // key-value 映射
	stop      uint32            // 停止应用 padding 的包序号
	md5       string            // scheme 的 MD5 值（小写 hex）
}

// newPaddingScheme 从原始字节创建 paddingScheme
func newPaddingScheme(rawScheme []byte) *paddingScheme {
	p := &paddingScheme{
		rawScheme: rawScheme,
		md5:       fmt.Sprintf("%x", md5.Sum(rawScheme)),
	}

	// 解析为 key-value map
	scheme := make(map[string]string)
	lines := strings.Split(string(rawScheme), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			scheme[parts[0]] = parts[1]
		}
	}

	if len(scheme) == 0 {
		return nil
	}

	// 解析 stop 字段
	if stop, err := strconv.Atoi(scheme["stop"]); err == nil {
		p.stop = uint32(stop)
	} else {
		return nil
	}

	p.scheme = scheme
	return p
}

// getDefaultPaddingScheme 返回默认的 padding scheme
func getDefaultPaddingScheme() *paddingScheme {
	return newPaddingScheme(defaultPaddingScheme)
}

// parsePaddingScheme 解析服务器发送的 padding scheme 字符串
func parsePaddingScheme(schemeStr string) (*paddingScheme, error) {
	if schemeStr == "" {
		return nil, nil
	}
	return newPaddingScheme([]byte(schemeStr)), nil
}

// GenerateRecordPayloadSizes 生成指定包序号的所有分片大小
// 返回的 slice 中，CheckMark (-1) 表示条件检查点
func (p *paddingScheme) GenerateRecordPayloadSizes(pkt uint32) []int {
	if p == nil {
		return nil
	}

	pktSizes := []int{}
	key := strconv.Itoa(int(pkt))
	s, ok := p.scheme[key]
	if !ok {
		return pktSizes
	}

	// 分割规则：例如 "400-500,c,500-1000,c,500-1000"
	sRanges := strings.Split(s, ",")
	for _, sRange := range sRanges {
		sRange = strings.TrimSpace(sRange)

		// 检查是否是 CheckMark
		if sRange == "c" {
			pktSizes = append(pktSizes, CheckMark)
			continue
		}

		// 解析 "min-max"
		sRangeMinMax := strings.Split(sRange, "-")
		if len(sRangeMinMax) != 2 {
			continue
		}

		_min, err := strconv.ParseInt(sRangeMinMax[0], 10, 64)
		if err != nil {
			continue
		}
		_max, err := strconv.ParseInt(sRangeMinMax[1], 10, 64)
		if err != nil {
			continue
		}

		// 确保 min <= max
		if _min > _max {
			_min, _max = _max, _min
		}

		if _min <= 0 || _max <= 0 {
			continue
		}

		// 生成随机大小
		if _min == _max {
			pktSizes = append(pktSizes, int(_min))
		} else {
			i, _ := rand.Int(rand.Reader, big.NewInt(_max-_min))
			pktSizes = append(pktSizes, int(i.Int64()+_min))
		}
	}

	return pktSizes
}

// getPadding0Size 获取包0（认证阶段）的 padding 大小
func getPadding0Size(scheme *paddingScheme) uint16 {
	if scheme == nil {
		return 30 // 默认值
	}

	sizes := scheme.GenerateRecordPayloadSizes(0)
	if len(sizes) > 0 && sizes[0] != CheckMark {
		return uint16(sizes[0])
	}

	return 30 // 默认值
}
