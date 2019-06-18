package snmp

import (
	"encoding/asn1"
	"fmt"
	"strings"

	"github.com/geoffgarside/ber"
	"github.com/k-sone/snmpgo"
)

// Message wraps requests and responses. It is rough copy of snmpgo.message
// with some minor conveniences, unfortunately it was not exported.
type Message struct {
	Version   snmpgo.SNMPVersion // SNMP version, only v1 and v2c are supported
	Community []byte             // Host's community string
	Pdu       snmpgo.Pdu         // PDU data, storing the OIDs and in the SNMP Response, associated values
}

// NewMessageWithOids is used when creating SNMP requests
func NewMessageWithOids(
	ver snmpgo.SNMPVersion,
	pduType snmpgo.PduType,
	community []byte,
	oids snmpgo.Oids,
) *Message {
	pdu := snmpgo.NewPduWithOids(ver, pduType, oids)
	if pduType == snmpgo.GetBulkRequest {
		pdu.SetNonrepeaters(0)
		pdu.SetMaxRepetitions(10)
	}
	return &Message{
		Version:   ver,
		Community: community,
		Pdu:       pdu,
	}
}

// NewMessageWithVarBinds is used when creating SNMP responses
func NewMessageWithVarBinds(ver snmpgo.SNMPVersion,
	pduType snmpgo.PduType,
	community []byte,
	varbinds snmpgo.VarBinds,
) *Message {
	return &Message{
		Version:   ver,
		Community: community,
		Pdu:       snmpgo.NewPduWithVarBinds(ver, pduType, varbinds),
	}
}

func (msg *Message) Marshal() (b []byte, err error) {
	var buf []byte
	raw := asn1.RawValue{Class: classUniversal, Tag: tagSequence, IsCompound: true}

	buf, err = asn1.Marshal(msg.Version)
	if err != nil {
		return
	}
	raw.Bytes = append(raw.Bytes, buf...)

	buf, err = asn1.Marshal(msg.Community)
	if err != nil {
		return
	}
	raw.Bytes = append(raw.Bytes, buf...)

	buf, err = msg.Pdu.Marshal()
	if err != nil {
		return nil, err
	}

	raw.Bytes = append(raw.Bytes, buf...)
	return asn1.Marshal(raw)
}

func (msg *Message) Unmarshal(b []byte) ([]byte, error) {
	ver, rest, next, err := unmarshalMessageVersion(b)
	if err != nil {
		return nil, err
	}

	err = msg.unmarshalInner(next)
	if err != nil {
		return nil, err
	}

	msg.Version = ver
	return rest, nil
}

func (msg *Message) unmarshalInner(b []byte) error {
	var community []byte
	next, err := ber.Unmarshal(b, &community)
	if err != nil {
		return err
	}

	msg.Community = community
	var pdu snmpgo.PduV1
	_, err = pdu.Unmarshal(next)
	msg.Pdu = &pdu
	return err
}

func (msg *Message) String() string {
	return fmt.Sprintf(
		`{"Version": "%s", "Community": "%s", "Pdu": %s}`,
		msg.Version, msg.Community, msg.Pdu.String())
}

func unmarshalMessageVersion(b []byte) (snmpgo.SNMPVersion, []byte, []byte, error) {
	var raw asn1.RawValue
	rest, err := ber.Unmarshal(b, &raw)
	if err != nil {
		return 0, nil, nil, err
	}
	if raw.Class != classUniversal || raw.Tag != tagSequence || !raw.IsCompound {
		return 0, nil, nil, asn1.StructuralError{Msg: fmt.Sprintf(
			"Invalid message object - Class [%02x], Tag [%02x] : [%s]",
			raw.Class, raw.Tag, toHexStr(b, " "))}
	}

	var version int
	next, err := ber.Unmarshal(raw.Bytes, &version)
	if err != nil {
		return 0, nil, nil, err
	}

	return snmpgo.SNMPVersion(version), rest, next, nil
}

func toHexStr(a []byte, sep string) string {
	s := make([]string, len(a))
	for i, b := range a {
		s[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(s, sep)
}
