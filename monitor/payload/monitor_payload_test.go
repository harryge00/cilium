// Copyright 2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package payload

import (
	"bytes"
	"encoding/gob"
	"testing"

	"github.com/cilium/cilium/pkg/comparator"
	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type PayloadSuite struct{}

var _ = Suite(&PayloadSuite{})

func (s *PayloadSuite) TestMeta_UnMarshalBinary(c *C) {
	meta1 := Meta{Size: 1234}
	buf, err := meta1.MarshalBinary()
	c.Assert(err, Equals, nil)

	var meta2 Meta
	err = meta2.UnmarshalBinary(buf)
	c.Assert(err, Equals, nil)

	c.Assert(meta1, comparator.DeepEquals, meta2)
}

func (s *PayloadSuite) TestPayload_UnMarshalBinary(c *C) {
	payload1 := Payload{
		Data: []byte{1, 2, 3, 4},
		Lost: 5243,
		CPU:  12,
		Type: 9,
	}
	buf, err := payload1.Encode()
	c.Assert(err, Equals, nil)

	var payload2 Payload
	err = payload2.Decode(buf)
	c.Assert(err, Equals, nil)

	c.Assert(payload1, comparator.DeepEquals, payload2)
}

func (s *PayloadSuite) TestWriteReadMetaPayload(c *C) {
	meta1 := Meta{Size: 1234}
	payload1 := Payload{
		Data: []byte{1, 2, 3, 4},
		Lost: 5243,
		CPU:  12,
		Type: 9,
	}

	var buf bytes.Buffer
	err := WriteMetaPayload(&buf, &meta1, &payload1)
	c.Assert(err, Equals, nil)

	var meta2 Meta
	var payload2 Payload
	err = ReadMetaPayload(&buf, &meta2, &payload2)
	c.Assert(err, Equals, nil)

	c.Assert(meta1, comparator.DeepEquals, meta2)
	c.Assert(payload1, comparator.DeepEquals, payload2)
}

func (s *PayloadSuite) BenchmarkWriteMetaPayload(c *C) {
	meta := Meta{Size: 1234}
	pl := Payload{
		Data: []byte{1, 2, 3, 4},
		Lost: 5243,
		CPU:  12,
		Type: 9,
	}

	// Do a first dry run to pre-allocate the buffer capacity.
	var buf bytes.Buffer
	err := WriteMetaPayload(&buf, &meta, &pl)
	c.Assert(err, Equals, nil)

	for i := 0; i < c.N; i++ {
		buf.Reset()
		err := WriteMetaPayload(&buf, &meta, &pl)
		c.Assert(err, Equals, nil)
	}
}

func (s *PayloadSuite) BenchmarkReadMetaPayload(c *C) {
	meta1 := Meta{Size: 1234}
	payload1 := Payload{
		Data: []byte{1, 2, 3, 4},
		Lost: 5243,
		CPU:  12,
		Type: 9,
	}

	var buf bytes.Buffer
	err := WriteMetaPayload(&buf, &meta1, &payload1)
	c.Assert(err, Equals, nil)

	var meta2 Meta
	var payload2 Payload
	for i := 0; i < c.N; i++ {
		readBuf := bytes.NewBuffer(buf.Bytes())
		err = ReadMetaPayload(readBuf, &meta2, &payload2)
		c.Assert(err, Equals, nil)
	}
}

func BenchmarkWriteMetaPayload(b *testing.B) {
	b.ReportAllocs()
	meta1 := Meta{Size: 1234}
	payload1 := Payload{
		Data: []byte{1, 2, 3, 4},
		Lost: 5243,
		CPU:  12,
		Type: 9,
	}

	// Fill the buffer once so it allocates enough ram so that we don't need to
	// reallocate again during the test
	var buf bytes.Buffer
	err := WriteMetaPayload(&buf, &meta1, &payload1)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		buf.Reset()
		err := WriteMetaPayload(&buf, &meta1, &payload1)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReadMetaPayload(b *testing.B) {
	b.ReportAllocs()
	payload1 := Payload{
		Data: []byte{1, 2, 3, 4},
		Lost: 5243,
		CPU:  12,
		Type: 9,
	}
	buf, err := payload1.Encode()
	if err != nil {
		b.Fatal(err)
	}

	var payload2 Payload
	for i := 0; i < b.N; i++ {
		err = payload2.Decode(buf)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGobEncode(b *testing.B) {
	b.ReportAllocs()
	pl := Payload{
		Data: []byte{1, 2, 3, 4},
		Lost: 5243,
		CPU:  12,
		Type: 9,
	}

	// Fill the buffer once so it allocates enough ram so that we don't need to
	// reallocate again during the test
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(pl)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		buf.Reset()
		err := enc.Encode(pl)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGobDecode(b *testing.B) {
	b.ReportAllocs()
	pl := Payload{
		Data: []byte{1, 2, 3, 4},
		Lost: 5243,
		CPU:  12,
		Type: 9,
	}

	var bufOriginal bytes.Buffer
	enc := gob.NewEncoder(&bufOriginal)
	err := enc.Encode(pl)
	if err != nil {
		b.Fatal(err)
	}

	var pl2 Payload
	var buf bytes.Buffer
	pristine := append([]byte{}, bufOriginal.Bytes()...)
	for i := 0; i < b.N; i++ {
		buf.Reset()
		buf.Write(pristine)
		dec := gob.NewDecoder(&buf)
		err := dec.Decode(&pl2)
		if err != nil {
			b.Fatal(err)
		}
	}
}
