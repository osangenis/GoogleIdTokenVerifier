package GoogleIdTokenVerifier

// TokenInfo is an ID token as defined in https://auth0.com/docs/tokens#id-tokens
// Access token used in token-based authentication to gain access to resources by using them as bearer tokens.
// Refresh token is a long-lived special kind of token used to obtain a renewed access token.
// ID token carries identity information encoded in the token itself, which must be a JWT. It must not contain any authorization information, or any audience information — it is merely an identifier for the user.
type TokenInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	AtHash        string `json:"at_hash"`
	Aud           string `json:"aud"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	Local         string `json:"locale"`
	Iss           string `json:"iss"`
	Azp           string `json:"azp"`
	Iat           int64  `json:"iat"`
	Exp           int64  `json:"exp"`
}
