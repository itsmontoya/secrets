package secrets

func New() (out *Secrets, err error) {
	var s Secrets
	if s.Raw, err = MakeRaw[Values](makeValues); err != nil {
		return
	}

	out = &s
	return
}

type Secrets struct {
	Raw[Values]
}
