package secrets

import (
	"crypto/aes"
	"encoding/json"
	"reflect"
	"testing"
)

func TestSecrets_Full(t *testing.T) {
	var err error
	orgID := "00000001"
	testValues := Values{
		"foo": "1",
		"bar": "2",
	}
	s := Secrets{
		v: testValues,
	}

	if err = s.Encrypt(orgID); err != nil {
		t.Fatal(err)
	}

	var marshalled []byte
	if marshalled, err = s.MarshalJSON(); err != nil {
		t.Fatal(err)
	}

	var out Secrets
	if err = json.Unmarshal(marshalled, &out); err != nil {
		t.Fatal(err)
	}

	if err = out.Values(orgID, func(v Values) {
		if v["foo"] != testValues["foo"] {
			t.Fatalf("invalid value for \"foo\", want %s and received %s", testValues["foo"], v["foo"])
		}

		if v["bar"] != testValues["bar"] {
			t.Fatalf("invalid value for \"bar\", want %s and received %s", testValues["bar"], v["bar"])
		}

	}); err != nil {
		t.Fatal(err)
	}

}

func TestSecrets_MarshalJSON(t *testing.T) {
	orgID := "00000001"
	oldMakeIV := makeIV
	defer func() { makeIV = oldMakeIV }()
	makeIV = func() (iv []byte, err error) {
		iv = make([]byte, aes.BlockSize)
		return
	}

	type testValue struct {
		Secrets *Secrets `json:"secrets,omitempty"`
	}

	type testcase struct {
		name    string
		value   testValue
		wantBs  []byte
		wantErr bool
	}

	tests := []testcase{
		{
			name:    "unset",
			value:   testValue{},
			wantBs:  []byte("{}"),
			wantErr: false,
		},
		{
			name: "empty",
			value: testValue{
				Secrets: &Secrets{},
			},
			wantBs:  []byte(`{"secrets":""}`),
			wantErr: false,
		},
		{
			name: "value",
			value: testValue{
				Secrets: &Secrets{
					v: Values{
						"foo": "bar",
					},
				},
			},
			wantBs:  []byte(`{"secrets":"00000000000000000000000000000000faffb48988620c35bea481d4f2"}`),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if err = tt.value.Secrets.Encrypt(orgID); err != nil {
				t.Fatal(err)
			}

			var gotBS []byte
			if gotBS, err = json.Marshal(tt.value); (err != nil) != tt.wantErr {
				t.Errorf("Secrets.MarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !reflect.DeepEqual(gotBS, tt.wantBs) {
				t.Errorf("Secrets.MarshalJSON() = %v, want %v", string(gotBS), string(tt.wantBs))
			}
		})
	}
}

func TestSecrets_UnmarshalJSON(t *testing.T) {
	oldMakeIV := makeIV
	defer func() { makeIV = oldMakeIV }()
	makeIV = func() (iv []byte, err error) {
		iv = make([]byte, aes.BlockSize)
		return
	}

	type testValue struct {
		Secrets *Secrets `json:"secrets,omitempty"`
	}

	type testcase struct {
		name    string
		json    []byte
		want    testValue
		wantErr bool
	}

	tests := []testcase{
		{
			name:    "unset",
			json:    []byte("{}"),
			want:    testValue{},
			wantErr: false,
		},
		{
			name: "empty",
			json: []byte(`{"secrets":""}`),
			want: testValue{
				Secrets: &Secrets{
					v: Values{},
				},
			},
			wantErr: false,
		},
		{
			name: "value",
			json: []byte(`{"secrets":"303030303030303100000000000000001c4a28b0eb880e401c6eb672d6"}`),
			want: testValue{
				Secrets: &Secrets{
					s: "303030303030303100000000000000001c4a28b0eb880e401c6eb672d6",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				got testValue
				err error
			)

			if err = json.Unmarshal(tt.json, &got); (err != nil) != tt.wantErr {
				t.Errorf("Secrets.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !compareSecrets(got.Secrets, tt.want.Secrets) {
				t.Errorf("Secrets.UnmarshalJSON() got = %+v, want %+v", got.Secrets, tt.want.Secrets)
			}

		})
	}
}

func compareSecrets(a, b *Secrets) (equals bool) {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil && b != nil:
		return false
	case a != nil && b == nil:
		return false
	case a.s != b.s:
		return false
	case len(a.v) == 0 && len(b.v) == 0:
		return true
	default:
		return reflect.DeepEqual(a.v, b.v)
	}
}
