package secrets

import (
	"encoding/json"
)

type Secrets struct {
	v Values
	s string
}

// Values will get the current values of the Secrets
func (s *Secrets) Values(key string, fn func(Values)) (err error) {
	switch {
	case len(s.v) > 0:
		fn(s.v)
	case len(s.s) == 0:
		s.v = Values{}
		fn(s.v)
	default:
		var v Values
		if v, err = makeValuesFromString(s.s, key); err != nil {
			return
		}

		fn(v)
	}

	return
}

// Encrypt will encrypt the underlying values
func (s *Secrets) Encrypt(key string) (err error) {
	if s == nil {
		return
	}

	if len(s.v) == 0 {
		s.s = ""
		return
	}

	var bs []byte
	if bs, err = json.Marshal(s.v); err != nil {
		return
	}

	if s.s, err = encrypt(bs, key); err != nil {
		return
	}

	s.v = nil
	return
}

func (s *Secrets) MarshalJSON() (bs []byte, err error) {
	if s == nil {
		return json.Marshal("")
	}

	return json.Marshal(s.s)
}

func (s *Secrets) UnmarshalJSON(bs []byte) (err error) {
	if len(bs) == 0 {
		return
	}

	var (
		sec Secrets
		v   Values
	)

	if err = json.Unmarshal(bs, &v); err == nil {
		*s = sec
		s.v = v
		return
	}

	if err = json.Unmarshal(bs, &sec.s); err != nil {
		return
	}

	*s = sec
	return
}
