// Copyright 2023 Red Hat, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build unit

package attestation

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/gkampitakis/go-snaps/snaps"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	ct "github.com/sigstore/cosign/v2/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/enterprise-contract/ec-cli/internal/signature"
	e "github.com/enterprise-contract/ec-cli/pkg/error"
)

type mockSignature struct {
	*mock.Mock
}

func (l mockSignature) Annotations() (map[string]string, error) {
	args := l.Called()

	return args.Get(0).(map[string]string), args.Error(1)
}

func (l mockSignature) Payload() ([]byte, error) {
	args := l.Called()

	return args.Get(0).([]byte), args.Error(1)
}

func (l mockSignature) Signature() ([]byte, error) {
	args := l.Called()

	return args.Get(0).([]byte), args.Error(1)
}

func (l mockSignature) Base64Signature() (string, error) {
	args := l.Called()

	return args.Get(0).(string), args.Error(1)
}

func (l mockSignature) Cert() (*x509.Certificate, error) {
	args := l.Called()

	return args.Get(0).(*x509.Certificate), args.Error(1)
}

func (l mockSignature) Chain() ([]*x509.Certificate, error) {
	args := l.Called()

	return args.Get(0).([]*x509.Certificate), args.Error(1)
}

func (l mockSignature) Bundle() (*bundle.RekorBundle, error) {
	args := l.Called()

	return args.Get(0).(*bundle.RekorBundle), args.Error(1)
}

func (l mockSignature) RFC3161Timestamp() (*bundle.RFC3161Timestamp, error) {
	args := l.Called()

	return args.Get(0).(*bundle.RFC3161Timestamp), args.Error(1)
}

func (l mockSignature) Digest() (v1.Hash, error) {
	args := l.Called()

	return args.Get(0).(v1.Hash), args.Error(1)
}

func (l mockSignature) DiffID() (v1.Hash, error) {
	args := l.Called()

	return args.Get(0).(v1.Hash), args.Error(1)
}

func (l mockSignature) Compressed() (io.ReadCloser, error) {
	args := l.Called()

	return args.Get(0).(io.ReadCloser), args.Error(1)
}

func (l mockSignature) Uncompressed() (io.ReadCloser, error) {
	args := l.Called()

	return args.Get(0).(io.ReadCloser), args.Error(1)
}

func (l mockSignature) Size() (int64, error) {
	args := l.Called()

	return args.Get(0).(int64), args.Error(1)
}

func (l mockSignature) MediaType() (types.MediaType, error) {
	args := l.Called()

	return args.Get(0).(types.MediaType), args.Error(1)
}

func TestSLSAProvenanceFromSignatureNilSignature(t *testing.T) {
	sp, err := SLSAProvenanceFromSignature(nil)
	assert.True(t, AT001.Alike(err), "Expecting `%v` to be alike: `%v`", err, AT001)
	assert.Nil(t, sp)
}

func TestSLSAProvenanceFromSignature(t *testing.T) {
	cases := []struct {
		name  string
		setup func(l *mockSignature)
		data  string
		err   e.Error
	}{
		{
			name: "media type error",
			setup: func(l *mockSignature) {
				l.On("MediaType").Return(types.MediaType(""), errors.New("expected"))
			},
			err: AT002.CausedByF("expected"),
		},
		{
			name: "no media type",
			setup: func(l *mockSignature) {
				l.On("MediaType").Return(types.MediaType(""), nil)
			},
			err: AT002.CausedByF(
				"Expecting media type of `application/vnd.dsse.envelope.v1+json`, received: ``"),
		},
		{
			name: "unsupported media type",
			setup: func(l *mockSignature) {
				l.On("MediaType").Return(types.MediaType("xxx"), nil)
			},
			err: AT002.CausedByF(
				"Expecting media type of `application/vnd.dsse.envelope.v1+json`, received: `xxx`"),
		},
		{
			name: "no payload JSON",
			setup: func(l *mockSignature) {
				l.On("MediaType").Return(types.MediaType(ct.DssePayloadType), nil)
				l.On("Uncompressed").Return(io.NopCloser(&bytes.Buffer{}), nil)
			},
			err: AT002.CausedByF("unexpected end of JSON input"),
		},
		{
			name: "empty payload JSON",
			data: "{}",
			setup: func(l *mockSignature) {
				payload := base64.StdEncoding.EncodeToString([]byte("{}"))
				l.On("MediaType").Return(types.MediaType(ct.DssePayloadType), nil)
				l.On("Uncompressed").Return(buffy(fmt.Sprintf(`{"payload":"%s"}`, payload)), nil)
			},
			err: AT003.CausedByF(""),
		},
		{
			name: "invalid attestation payload JSON",
			setup: func(l *mockSignature) {
				sig1 := `{"keyid": "key-id-1", "sig": "sig-1"}`
				payload := fmt.Sprintf(`{"signatures": [%s]}}}}}`, sig1)
				l.On("MediaType").Return(types.MediaType(ct.DssePayloadType), nil)
				l.On("Uncompressed").Return(buffy(payload), nil)
			},
			err: AT002.CausedByF("invalid character '}' after top-level value"),
		},
		{
			name: "invalid statement JSON",
			setup: func(l *mockSignature) {
				sig1 := `{"keyid": "key-id-1", "sig": "sig-1"}`
				l.On("MediaType").Return(types.MediaType(ct.DssePayloadType), nil)
				l.On("Uncompressed").Return(buffy(
					fmt.Sprintf(`{"signatures": [%s], "payload": "not-base64"}`, sig1),
				), nil)
			},
			err: AT002.CausedByF("illegal base64 data at input byte 3"),
		},
		{
			name: "invalid statement JSON",
			setup: func(l *mockSignature) {
				sig1 := `{"keyid": "key-id-1", "sig": "sig-1"}`
				payload := encode(`{
					"_type": "https://in-toto.io/Statement/v0.1",
					"predicateType":"https://slsa.dev/provenance/v0.2",
					"predicate":{} }}}}}}}}}
				}`)
				l.On("MediaType").Return(types.MediaType(ct.DssePayloadType), nil)
				l.On("Uncompressed").Return(buffy(
					fmt.Sprintf(`{"signatures": [%s], "payload": "%s"}`, sig1, payload),
				), nil)
			},
			err: AT002.CausedByF("invalid character '}' after top-level value"),
		},
		{
			name: "unexpected predicate type",
			setup: func(l *mockSignature) {
				sig1 := `{"keyid": "key-id-1", "sig": "sig-1"}`
				payload := encode(`{
					"_type": "https://in-toto.io/Statement/v0.1",
					"predicateType":"kaboom"
				}`)
				l.On("MediaType").Return(types.MediaType(ct.DssePayloadType), nil)
				l.On("Uncompressed").Return(buffy(
					fmt.Sprintf(`{"signatures": [%s], "payload": "%s"}`, sig1, payload),
				), nil)
			},
			err: AT004.CausedByF("kaboom"),
		},
		{
			name: "cannot create entity signature",
			data: `{
				"_type": "https://in-toto.io/Statement/v0.1",
				"predicateType": "https://slsa.dev/provenance/v0.2",
				"predicate": {"buildType": "https://my.build.type"}
			}`,
			setup: func(l *mockSignature) {
				payload := encode(`{
					"_type": "https://in-toto.io/Statement/v0.1",
					"predicateType": "https://slsa.dev/provenance/v0.2",
					"predicate": {"buildType":"https://my.build.type"}
				}`)
				l.On("MediaType").Return(types.MediaType(ct.DssePayloadType), nil)
				l.On("Uncompressed").Return(buffy(fmt.Sprintf(`{"payload":"%s"}`, payload)), nil)
				l.On("Base64Signature").Return("", errors.New("kaboom"))
			},
			err: AT005.CausedByF("kaboom"),
		},
		{
			name: "valid with signature from payload",
			data: `{
				"_type": "https://in-toto.io/Statement/v0.1",
				"predicateType": "https://slsa.dev/provenance/v0.2",
				"predicate": {"buildType": "https://my.build.type"}
			}`,
			setup: func(l *mockSignature) {
				sig1 := `{"keyid": "key-id-1", "sig": "sig-1"}`
				sig2 := `{"keyid": "key-id-2", "sig": "sig-2"}`
				payload := encode(`{
					"_type": "https://in-toto.io/Statement/v0.1",
					"predicateType": "https://slsa.dev/provenance/v0.2",
					"predicate": {"buildType": "https://my.build.type"}
				}`)
				l.On("MediaType").Return(types.MediaType(ct.DssePayloadType), nil)
				l.On("Uncompressed").Return(buffy(
					fmt.Sprintf(`{"payload": "%s", "signatures": [%s, %s]}`, payload, sig1, sig2),
				), nil)
				l.On("Base64Signature").Return("", nil)
				l.On("Cert").Return(&x509.Certificate{}, nil)
				l.On("Chain").Return([]*x509.Certificate{}, nil)
			},
		},
		{
			name: "valid with signature from certificate",
			data: `{
				"_type": "https://in-toto.io/Statement/v0.1",
				"predicateType": "https://slsa.dev/provenance/v0.2",
				"predicate": {"buildType": "https://my.build.type"}
			}`,
			setup: func(l *mockSignature) {
				sig1 := `{"keyid": "ignored-1", "sig": "ignored-1"}`
				sig2 := `{"keyid": "ignored-2", "sig": "ignored-2"}`
				payload := encode(`{
					"_type": "https://in-toto.io/Statement/v0.1",
					"predicateType": "https://slsa.dev/provenance/v0.2",
					"predicate": {"buildType": "https://my.build.type"}
				}`)
				l.On("MediaType").Return(types.MediaType(ct.DssePayloadType), nil)
				l.On("Uncompressed").Return(buffy(
					fmt.Sprintf(`{"payload": "%s", "signatures": [%s, %s]}`, payload, sig1, sig2),
				), nil)
				l.On("Base64Signature").Return("sig-from-cert", nil)
				l.On("Cert").Return(signature.ParseChainguardReleaseCert(), nil)
				l.On("Chain").Return(signature.ParseSigstoreChainCert(), nil)
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sig := mockSignature{&mock.Mock{}}

			if c.setup != nil {
				c.setup(&sig)
			}

			sp, err := SLSAProvenanceFromSignature(sig)
			if c.err == nil {
				require.Nil(t, err)
				require.NotNil(t, sp)
			} else {
				require.Nil(t, sp)
				assert.True(t, c.err.Alike(err), "Expecting `%v` to be alike: `%v`", err, c.err)
				return
			}

			if c.data == "" {
				assert.Nil(t, sp.Data())
			} else {
				assert.JSONEq(t, c.data, string(sp.Data()))
			}
			snaps.MatchSnapshot(t, sp.Statement())
		})
	}
}

func encode(payload string) string {
	return base64.StdEncoding.EncodeToString([]byte(payload))
}

func buffy(data string) io.ReadCloser {
	return io.NopCloser(bytes.NewBufferString(data))
}
