package claims

type Err string

var (
	ErrTokenRole Err = "Token 角色无效"
	ErrTokenPrv  Err = "Token 模型无效"
)

func (e Err) Error() string {
	return string(e)
}
