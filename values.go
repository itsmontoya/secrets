package secrets

import "encoding/json"

func makeValues() (out Values) {
	return make(Values)
}

type Values map[string]string

func (v Values) String() string {
	bs, _ := json.Marshal(v)
	return string(bs)
}
