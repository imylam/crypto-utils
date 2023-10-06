package signature

type Verifier interface {
	Algo() string
	Verify(string, string) error
}
