package jwt

type Err string

var (
	ErrJWTNotInit                Err = "JWT 未初始化"
	ErrInvalidKey                Err = "密钥无效"
	ErrInvalidKeyType            Err = "密钥类型无效"
	ErrHashUnavailable           Err = "hash 算法不可用"
	ErrTokenMalformed            Err = "Token 格式错误"
	ErrTokenUnverifiable         Err = "Token 无法验证"
	ErrTokenSignatureInvalid     Err = "Token 签名无效"
	ErrTokenRequiredClaimMissing Err = "Token 缺少必要的参数"
	ErrTokenExpired              Err = "Token 已过期"
	ErrTokenUsedBeforeIssued     Err = "Token 已使用"
	ErrTokenInvalidIssuer        Err = "Token 签发者无效"
	ErrTokenInvalidSubject       Err = "Token 主题无效"
	ErrTokenNotValidYet          Err = "Token 尚未生效"
	ErrTokenInvalidID            Err = "Token ID 无效"
	ErrTokenInvalidClaims        Err = "Token 参数无效"
	ErrTokenInvalid              Err = "Token 无效"
	ErrTokenRole                 Err = "Token 角色无效"
	ErrTokenPrv                  Err = "Token 模型无效"
)

func (e Err) Error() string {
	return string(e)
}
