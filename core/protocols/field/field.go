// core/protocols/field/field.go 负责协议字段的定义与相关操作
package field

// Field 结构体表示一个协议字段，包括字段名和默认值
type Field struct {
	Key   string // 字段名
	Value string // 默认值
}

// NilStrField 返回一个字段名为 key 的 Field 实例，默认值为空字符串
func NilStrField(key string) Field {
	return Field{
		Key:   key,
		Value: "",
	}
}

// NoneField 返回一个字段名为 key 的 Field 实例，默认值为 "none"
func NoneField(key string) Field {
	return Field{
		Key:   key,
		Value: "none",
	}
}

// NewField 返回一个字段名为 key，默认值为 value 的 Field 实例
func NewField(key, value string) Field {
	return Field{
		Key:   key,
		Value: value,
	}
}

var (
	NetworkType     Field = NewField("type", "tcp")        // 协议的传输方式, 可选值 tcp/kcp/ws/http/quic/grpc
	VLessEncryption       = NoneField("encryption")        // 加密, VLESS可选值 none
	VMessEncryption       = NewField("encryption", "auto") // 加密,  VMess可选值 auto/aes-128-gcm/chacha20-poly1305/none
	TlsSecurity           = NoneField("security")          // 设定底层传输所使用的 TLS 类型, 可选值有 none/tls/xtls/reality

	// TCP
	TCPHeaderType = NoneField("headerType")

	// HTTP/2
	H2Path = NewField("path", "/")
	H2Host = NilStrField("host")

	// WebSocket
	WsPath = NewField("path", "/")
	WsHost = NilStrField("host")

	// SplitHTTP
	SpPath = NewField("path", "/")
	SpHost = NilStrField("host")
	SpMode = NewField("mode", "auto")

	// xhttp （只有首字母大写的变量才能被包外访问）
	XhPath = NewField("path", "/")
	XhHost = NilStrField("host")
	XhMode = NewField("mode", "auto")

	// mKCP
	MkcpHeaderType = NoneField("headerType") // mKCP 的伪装头部类型, 可选值 none/srtp/utp/wechat-video/dtls/wireguard
	Seed           = NilStrField("seed")     // mKCP 种子

	// QUIC
	QuicSecurity   = NoneField("quicSecurity") // QUIC 的加密方式, 可选值 none/aes-128-gcm/chacha20-poly1305
	QuicKey        = NilStrField("key")        //  QUIC 的加密方式不为 none 时的加密密钥
	QuicHeaderType = NoneField("headerType")   // QUIC 的伪装头部类型。其他同 mKCP headerType 字段定义

	// gRPC
	GrpcServiceName = NilStrField("serviceName")
	GrpcMode        = NewField("mode", "gun") // gRPC 的传输模式, 可选值 gun/multi/guna

	Security = NoneField("security")
	SNI      = NilStrField("sni")  // TLS SNI
	Alpn     = NilStrField("alpn") // alpn 多选 h2,http/1.1
	Flow     = NilStrField("flow") // XTLS 的流控方式，可选值xtls-rprx-direct/xtls-rprx-splice

	FingerPrint = NewField("fp", "chrome") // TLS Client Hello 指纹
	PublicKey   = NilStrField("pbk")       // REALITY的公钥
	ShortId     = NilStrField("sid")       // REALITY 的 ID
	SpiderX     = NilStrField("spx")       // REALITY 的爬虫
)
