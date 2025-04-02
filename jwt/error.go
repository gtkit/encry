package jwt

type Err string

var (
	ErrInvalidKey                Err = "key is invalid"
	ErrInvalidKeyType            Err = "key is of invalid type"
	ErrHashUnavailable           Err = "the requested hash function is unavailable"
	ErrTokenMalformed            Err = "token is malformed"
	ErrTokenUnverifiable         Err = "token is unverifiable"
	ErrTokenSignatureInvalid     Err = "token signature is invalid"
	ErrTokenRequiredClaimMissing Err = "token is missing required claim"
	ErrTokenInvalidAudience      Err = "token has invalid audience"
	ErrTokenExpired              Err = "token is expired"
	ErrTokenUsedBeforeIssued     Err = "token used before issued"
	ErrTokenInvalidIssuer        Err = "token has invalid issuer"
	ErrTokenInvalidSubject       Err = "token has invalid subject"
	ErrTokenNotValidYet          Err = "token is not valid yet"
	ErrTokeninvalidID            Err = "token has invalid id"
	ErrTokenInvalidClaims        Err = "token has invalid claims"
	ErrInvalidType               Err = "invalid type for claim"
	ErrTokenInvalid              Err = "couldn't handle this token"
)

func (e Err) Error() string {
	return string(e)
}
