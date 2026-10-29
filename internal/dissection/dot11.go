package dissection

import (
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func dot11InformationElementPrefix(layer gopacket.Layer) (int, bool) {
	switch layer.(type) {
	case *layers.Dot11MgmtAssociationReq:
		return 4, true
	case *layers.Dot11MgmtAssociationResp, *layers.Dot11MgmtReassociationResp:
		return 6, true
	case *layers.Dot11MgmtReassociationReq:
		return 10, true
	case *layers.Dot11MgmtProbeReq, *layers.Dot11MgmtATIM:
		return 0, true
	case *layers.Dot11MgmtProbeResp, *layers.Dot11MgmtBeacon:
		return 12, true
	default:
		return 0, false
	}
}
