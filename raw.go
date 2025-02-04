package secrets

import (
	"encoding/json"
)

func NewRaw[T any](g Generator[T]) (out *Raw[T]) {
	r := MakeRaw(g)
	out = &r
	return
}

func MakeRaw[T any](g Generator[T]) (out Raw[T]) {
	out.g = g
	return
}

type Raw[T any] struct {
	g Generator[T]

	valueIsSet bool

	v T
	s string
}

// Values will get the current values of the Raw
func (r *Raw[T]) Values(key string, fn func(T) error) (err error) {
	switch {
	case r.valueIsSet:
	case len(r.s) == 0:
		r.v = r.g()
	default:
		var v T
		if err = decryptToJSON(r.s, key, &v); err != nil {
			return
		}

		r.v = v
	}

	fn(r.v)
	return
}

// Encrypt will encrypt the underlying values
func (r *Raw[T]) Encrypt(key string) (err error) {
	if !r.valueIsSet {
		return
	}

	var bs []byte
	if bs, err = json.Marshal(r.v); err != nil {
		return
	}

	if r.s, err = encrypt(bs, key); err != nil {
		return
	}

	var zero T
	r.v = zero
	return
}

func (r *Raw[T]) MarshalJSON() (bs []byte, err error) {
	if r == nil {
		return json.Marshal("")
	}

	return json.Marshal(r.s)
}

func (r *Raw[T]) UnmarshalJSON(bs []byte) (err error) {
	if len(bs) == 0 {
		return
	}

	var (
		raw Raw[T]
		v   T
	)

	if err = json.Unmarshal(bs, &v); err == nil {
		*r = raw
		r.v = v
		r.valueIsSet = true
		return
	}

	if err = json.Unmarshal(bs, &raw.s); err != nil {
		return
	}

	*r = raw
	return
}

func (r *Raw[T]) String() string {
	return r.s
}
