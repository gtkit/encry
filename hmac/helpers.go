package hmac

import (
	"encoding/base64"
	"encoding/hex"
)

func signatureCandidates(sign string) [][]byte {
	candidates := [][]byte{[]byte(sign)}

	if decoded, err := hex.DecodeString(sign); err == nil {
		candidates = append(candidates, decoded)
	}

	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.RawURLEncoding,
	}
	for _, encoding := range encodings {
		if decoded, err := encoding.DecodeString(sign); err == nil {
			candidates = append(candidates, decoded)
		}
	}

	return candidates
}
