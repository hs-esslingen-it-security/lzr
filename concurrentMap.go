/*
Copyright 2020 The Board of Trustees of The Leland Stanford Junior University

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

This file also includes code from
https://github.com/orcaman/concurrent-map/blob/master/concurrent_map.go
which is licensed under the MIT license (Copyright (c) 2014 streamrail)
*/

package lzr

//"fmt"
//"os"

var SHARD_COUNT = 4096

/* FOR PACKET_METADATA */
//is Processing for goPackets
func (m myCsMap) IsStartProcessing(p *packet_metadata) (bool, bool) {
	// Get shard
	pKey := constructKey(p)
	p_out, ok := m.Load(pKey)

	if !ok {
		return false, false
	}
	if !p_out.Packet.Processing {
		p_out.Packet.startProcessing()
		return true, true
	}
	return true, false

}

func (m myCsMap) StartProcessing(p *packet_metadata) bool {

	// Get shard
	pKey := constructKey(p)
	p_out, ok := m.Load(pKey)
	if !ok {
		return false
	}
	p_out.Packet.startProcessing()
	return ok

}

func (m myCsMap) FinishProcessing(p *packet_metadata) bool {

	// Get shard
	pKey := constructKey(p)
	p_out, ok := m.Load(pKey)
	if !ok {
		return false
	}
	p_out.Packet.finishedProcessing()
	return ok

}

/* Meta functions */
func fnv32(key string) uint32 {
	hash := uint32(2166136261)
	const prime32 = uint32(16777619)
	for i := 0; i < len(key); i++ {
		hash *= prime32
		hash ^= uint32(key[i])
	}
	return hash
}
