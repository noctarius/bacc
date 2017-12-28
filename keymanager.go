package bacc

type KeyManager interface {
	GetKey(fingerprint string) ([]byte, error)
}