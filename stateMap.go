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
*/
package lzr

import (
	"fmt"
	"math/bits"
	"strconv"

	csmap "github.com/mhmtszr/concurrent-swiss-map"
)

type myCsMap struct {
	csmap.CsMap[uint, *packet_state]
}

/* keeps state by storing the packet that was received
 * and within the packet stores the expected response.
 * storing received as to what was sent b/c want to know
 * perhaps need to wait some more
 */
func ConstructPacketStateMap(opts *options) *myCsMap {
	ipMeta := &myCsMap{*csmap.Create[uint, *packet_state](
		// set the number of map shards. the default value is 32.
		csmap.WithShardCount[uint, *packet_state](4096),
	)}
	return ipMeta
}

// concatenateBits concatenates two bit sequences represented as integers
func concatenateBits(a uint, b uint) uint {
	// Shift the first bit sequence to the left by the length of the second sequence
	shiftedA := uint(a) << bits.Len(b)
	// Combine the two sequences using a bitwise OR operation
	combined := shiftedA | uint(b)
	return combined
}

func constructKey(packet *packet_metadata) uint {
	ip, e := strconv.Atoi(packet.Saddr)
	if e == nil {
		return concatenateBits(uint(ip), uint(packet.Sport))
	}
	return 0
}

func constructParentKey(packet *packet_metadata, parentSport int) uint {

	ip, e := strconv.Atoi(packet.Saddr)
	if e == nil {
		return concatenateBits(uint(ip), uint(parentSport))
	}
	return 0
}

func (ipMeta *myCsMap) metaContains(p *packet_metadata) bool {

	pKey := constructKey(p)
	return ipMeta.Has(pKey)

}

func (ipMeta *myCsMap) find(p *packet_metadata) (*packet_metadata, bool) {
	pKey := constructKey(p)
	ps, ok := ipMeta.Load(pKey)
	if ok {
		return ps.Packet, ok
	}
	return nil, ok
}

func (ipMeta *myCsMap) update(p *packet_metadata) {

	pKey := constructKey(p)
	ps, ok := ipMeta.Load(pKey)
	if !ok {
		ps = &packet_state{
			Packet:       p,
			Ack:          false,
			HandshakeNum: 0,
		}
	} else {
		ps.Packet = p
	}
	ipMeta.Store(pKey, ps)
}

func (ipMeta *myCsMap) incHandshake(p *packet_metadata) bool {
	pKey := constructKey(p)
	ps, ok := ipMeta.Load(pKey)
	if ok {
		ps.HandshakeNum += 1
		ipMeta.Store(pKey, ps)
	}
	return ok
}

func (ipMeta *myCsMap) updateAck(p *packet_metadata) bool {
	pKey := constructKey(p)
	ps, ok := ipMeta.Load(pKey)
	if ok {
		ps.Ack = true
		ipMeta.Store(pKey, ps)
	}
	return ok
}

func (ipMeta *myCsMap) getAck(p *packet_metadata) bool {
	pKey := constructKey(p)
	ps, ok := ipMeta.Load(pKey)
	if ok {
		return ps.Ack
	}
	return false
}

func (ipMeta *myCsMap) incEphemeralResp(p *packet_metadata, sport int) bool {
	pKey := constructParentKey(p, sport)
	ps, ok := ipMeta.Load(pKey)
	if ok {
		ps.EphemeralRespNum += 1
		ipMeta.Store(pKey, ps)
	}
	return ok
}

func (ipMeta *myCsMap) getEphemeralRespNum(p *packet_metadata) int {
	pKey := constructKey(p)
	ps, ok := ipMeta.Load(pKey)
	if ok {
		return ps.EphemeralRespNum
	}
	return 0
}

func (ipMeta *myCsMap) getHyperACKtiveStatus(p *packet_metadata) bool {
	pKey := constructKey(p)
	ps, ok := ipMeta.Load(pKey)
	if ok {
		return ps.HyperACKtive
	}
	return false
}

func (ipMeta *myCsMap) setHyperACKtiveStatus(p *packet_metadata) bool {
	pKey := constructKey(p)
	ps, ok := ipMeta.Load(pKey)
	if ok {
		ps.HyperACKtive = true
		ipMeta.Store(pKey, ps)
	}
	return ok
}

func (ipMeta *myCsMap) setParentSport(p *packet_metadata, sport int) bool {
	pKey := constructKey(p)
	ps, ok := ipMeta.Load(pKey)
	if ok {
		ps.ParentSport = sport
		ipMeta.Store(pKey, ps)
	}
	return ok
}

func (ipMeta *myCsMap) getParentSport(p *packet_metadata) int {
	pKey := constructKey(p)
	ps, ok := ipMeta.Load(pKey)
	if ok {
		return ps.ParentSport
	}
	return 0
}

func (ipMeta *myCsMap) recordEphemeral(p *packet_metadata, ephemerals []packet_metadata) bool {

	pKey := constructKey(p)
	ps, ok := ipMeta.Load(pKey)
	if ok {
		ps.EphemeralFilters = append(ps.EphemeralFilters, ephemerals...)
		ipMeta.Store(pKey, ps)
	}
	return ok

}

func (ipMeta *myCsMap) getEphemeralFilters(p *packet_metadata) ([]packet_metadata, bool) {

	pKey := constructKey(p)
	ps, ok := ipMeta.Load(pKey)
	if ok {
		return ps.EphemeralFilters, ok
	}
	return nil, ok

}

func (ipMeta *myCsMap) updateData(p *packet_metadata) bool {
	pKey := constructKey(p)
	ps, ok := ipMeta.Load(pKey)
	if ok {
		ps.Data = true
		ipMeta.Store(pKey, ps)
	}
	return ok
}

func (ipMeta *myCsMap) getData(p *packet_metadata) bool {
	pKey := constructKey(p)
	ps, ok := ipMeta.Load(pKey)
	if ok {
		return ps.Data
	}
	return false
}

func (ipMeta *myCsMap) getHandshake(p *packet_metadata) int {
	pKey := constructKey(p)
	ps, ok := ipMeta.Load(pKey)
	if ok {
		return ps.HandshakeNum
	}
	return 0
}

func (ipMeta *myCsMap) incrementCounter(p *packet_metadata) bool {

	pKey := constructKey(p)
	ps, ok := ipMeta.Load(pKey)
	if !ok {
		return false
	}
	ps.Packet.incrementCounter()
	ipMeta.Store(pKey, ps)
	return true

}

func (ipMeta *myCsMap) remove(packet *packet_metadata) *packet_metadata {
	packet.ACKed = ipMeta.getAck(packet)
	packetKey := constructKey(packet)
	ipMeta.Delete(packetKey)
	return packet
}

func verifySA(pMap *packet_metadata, pRecv *packet_metadata) bool {

	if pRecv.SYN && pRecv.ACK {
		if pRecv.Acknum == pMap.Seqnum+1 {
			return true
		}
	} else {

		if (pRecv.Seqnum == (pMap.Seqnum)) || (pRecv.Seqnum == (pMap.Seqnum + 1)) {
			if pRecv.Acknum == (pMap.Acknum + pMap.LZRResponseL) {
				return true
			}
			if pRecv.Acknum == 0 { //for RSTs
				return true
			}
		}
	}
	return false

}

// TODO: eventually remove the act of updating packet with hyperactive flag to
// another packet func
func (ipMeta *myCsMap) verifyScanningIP(pRecv *packet_metadata) bool {

	pRecvKey := constructKey(pRecv)
	//first check that IP itself is being scanned
	ps, ok := ipMeta.Load(pRecvKey)
	if !ok {
		return false
	}
	pMap := ps.Packet

	//second check that 4-tuple matches with default packet
	if (pMap.Saddr == pRecv.Saddr) && (pMap.Dport == pRecv.Dport) &&
		(pMap.Sport == pRecv.Sport) {

		if verifySA(pMap, pRecv) {
			return true
		}
	}

	/*//lets re-query for the ACKtive packets
	pRecv.HyperACKtive = true
	pRecvKey = constructKey(pRecv)
	ps, ok = ipMeta.Get( pRecvKey )
	if !ok {
		pRecv.HyperACKtive = false
		return false
	}
	pMap = ps.Packet

	if verifySA( pMap, pRecv) {
		return true
	}
	pRecv.HyperACKtive = false
	*/
	if DebugOn() {
		fmt.Println(pMap.Saddr, "====")
		fmt.Println("recv seq num:", pRecv.Seqnum)
		fmt.Println("stored seqnum: ", pMap.Seqnum)
		fmt.Println("recv ack num:", pRecv.Acknum)
		fmt.Println("stored acknum: ", pMap.Acknum)
		fmt.Println("received response length: ", len(pRecv.Data))
		fmt.Println("stored response length: ", pMap.LZRResponseL)
		fmt.Println(pMap.Saddr, "====")
	}
	return false

}
