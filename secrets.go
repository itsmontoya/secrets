package secrets

func New() (out *Secrets, err error) {
	var s Secrets
	s.Raw = MakeRaw[Values](makeValues)
	out = &s
	return
}

type Secrets struct {
	Raw[Values]
}
