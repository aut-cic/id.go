package ldap

import ber "github.com/go-asn1-ber/asn1-ber"

type ldapControlServerPolicyHints struct {
	oid string
}

func (c *ldapControlServerPolicyHints) GetControlType() string {
	return c.oid
}

func (c *ldapControlServerPolicyHints) Encode() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString,
		c.GetControlType(), "Control Type (LDAP_SERVER_POLICY_HINTS_OID)"))
	packet.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, true, "Criticality"))

	p2 := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Control Value (Policy Hints)")
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "PolicyHintsRequestValue")
	seq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 1, "Flags"))
	p2.AppendChild(seq)
	packet.AppendChild(p2)

	return packet
}

func (c *ldapControlServerPolicyHints) String() string {
	return "Enforce password history policies during password set: " + c.GetControlType()
}
