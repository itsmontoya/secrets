package secrets

import "encoding/json"

func makeValues() (out Values) {
	return make(Values)
}

func makeValuesFromString(str, key string) (out Values, err error) {
	if len(str) == 0 {
		return
	}

	var decrypted []byte
	if decrypted, err = decrypt(str, key); err != nil {
		return
	}

	err = json.Unmarshal(decrypted, &out)
	return
}

type Values map[string]string

func (v Values) String() string {
	bs, _ := json.Marshal(v)
	return string(bs)
}
