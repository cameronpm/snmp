package snmp

// ASN.1 Class
const (
	classUniversal = iota
	classApplication
	classContextSpecific
	classPrivate
)

// ASN.1 Tag
const (
	tagInteger          = 0x02
	tagOctetString      = 0x04
	tagNull             = 0x05
	tagObjectIdentifier = 0x06
	tagSequence         = 0x10
	tagIpaddress        = 0x40
	tagCounter32        = 0x41
	tagGauge32          = 0x42
	tagTimeTicks        = 0x43
	tagOpaque           = 0x44
	tagCounter64        = 0x46
	tagNoSucheObject    = 0x80
	tagNoSucheInstance  = 0x81
	tagEndOfMibView     = 0x82
)
