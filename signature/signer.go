package signature

type Signer interface {
	Algo() string
	Sign(string) (string, error)
}
