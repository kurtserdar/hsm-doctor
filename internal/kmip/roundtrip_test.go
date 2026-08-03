package kmip

import (
	"net"
	"testing"
	"time"

	kmip "github.com/gemalto/kmip-go"
	"github.com/gemalto/kmip-go/kmip14"
	"github.com/gemalto/kmip-go/ttlv"
)

// locateResponsePayload marshals to a Locate response.
type locateResponsePayload struct {
	UniqueIdentifier []string
}

// getAttributesResponsePayload marshals to a GetAttributes response.
type getAttributesResponsePayload struct {
	UniqueIdentifier string
	Attribute        []kmip.Attribute
}

// fakeServer answers KMIP requests over conn from a fixed object set. It
// exercises the client's real TTLV encoding and decoding.
func fakeServer(t *testing.T, conn net.Conn, attrs map[string][]kmip.Attribute) {
	t.Helper()
	defer conn.Close()
	for {
		req, err := readTTLV(conn)
		if err != nil {
			return // client hung up
		}
		op, uid := requestOpAndUID(req)
		var payload interface{}
		switch op {
		case kmip14.OperationDiscoverVersions:
			payload = kmip.DiscoverVersionsResponsePayload{ProtocolVersion: []kmip.ProtocolVersion{
				{ProtocolVersionMajor: 1, ProtocolVersionMinor: 4},
				{ProtocolVersionMajor: 1, ProtocolVersionMinor: 2},
			}}
		case kmip14.OperationLocate:
			var ids []string
			for id := range attrs {
				ids = append(ids, id)
			}
			payload = locateResponsePayload{UniqueIdentifier: ids}
		case kmip14.OperationGetAttributes:
			payload = getAttributesResponsePayload{UniqueIdentifier: uid, Attribute: attrs[uid]}
		default:
			return
		}
		resp := kmip.ResponseMessage{
			ResponseHeader: kmip.ResponseHeader{
				ProtocolVersion: kmip.ProtocolVersion{ProtocolVersionMajor: 1, ProtocolVersionMinor: 4},
				BatchCount:      1,
			},
			BatchItem: []kmip.ResponseBatchItem{{
				Operation:       op,
				ResultStatus:    kmip14.ResultStatusSuccess,
				ResponsePayload: payload,
			}},
		}
		b, err := ttlv.Marshal(resp)
		if err != nil {
			t.Errorf("marshal response: %v", err)
			return
		}
		if _, err := conn.Write(b); err != nil {
			return
		}
	}
}

func requestOpAndUID(req ttlv.TTLV) (kmip14.Operation, string) {
	var op kmip14.Operation
	var uid string
	for t := req.ValueStructure(); len(t) > 0; t = t.Next() {
		if t.Tag() != kmip14.TagBatchItem {
			continue
		}
		for b := t.ValueStructure(); len(b) > 0; b = b.Next() {
			switch b.Tag() {
			case kmip14.TagOperation:
				op = kmip14.Operation(b.ValueEnumeration())
			case kmip14.TagRequestPayload:
				for p := b.ValueStructure(); len(p) > 0; p = p.Next() {
					if p.Tag() == kmip14.TagUniqueIdentifier {
						uid = p.ValueTextString()
					}
				}
			}
		}
	}
	return op, uid
}

func attr(name string, value interface{}) kmip.Attribute {
	return kmip.Attribute{AttributeName: name, AttributeValue: value}
}

func TestClientRoundTrip(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	objs := map[string][]kmip.Attribute{
		"100": {
			attr("Object Type", kmip14.ObjectTypePublicKey),
			attr("Cryptographic Algorithm", kmip14.CryptographicAlgorithmRSA),
			attr("Cryptographic Length", int32(1024)),
			attr("State", kmip14.StateActive),
			attr("Cryptographic Usage Mask", int32(kmip14.CryptographicUsageMaskVerify)),
			attr("Name", kmip.Name{NameValue: "weak-rsa", NameType: kmip14.NameTypeUninterpretedTextString}),
		},
	}
	go fakeServer(t, serverConn, objs)

	c := newClient(clientConn, 5*time.Second)
	defer c.Close()

	if err := c.discoverVersions(); err != nil {
		t.Fatalf("discoverVersions: %v", err)
	}
	if c.ProtocolVersion() != "1.4" {
		t.Errorf("negotiated version = %s, want 1.4", c.ProtocolVersion())
	}
	ids, err := c.locateAll()
	if err != nil {
		t.Fatalf("locateAll: %v", err)
	}
	if len(ids) != 1 || ids[0] != "100" {
		t.Fatalf("locateAll = %v, want [100]", ids)
	}
	obj, err := c.getObject("100")
	if err != nil {
		t.Fatalf("getObject: %v", err)
	}
	if obj.Algorithm != "RSA" || obj.Length != 1024 {
		t.Errorf("algorithm/length wrong: %+v", obj)
	}
	if obj.Type != "PublicKey" || obj.State != "Active" {
		t.Errorf("type/state wrong: %+v", obj)
	}
	if len(obj.Names) != 1 || obj.Names[0] != "weak-rsa" {
		t.Errorf("name wrong: %+v", obj.Names)
	}
	if len(obj.UsageMask) != 1 || obj.UsageMask[0] != "Verify" {
		t.Errorf("usage mask wrong: %+v", obj.UsageMask)
	}

	// The full inventory + posture path flags the weak key.
	rep := Evaluate(&Inventory{Objects: []Object{obj}})
	if !has(rep, "KMIP-001") {
		t.Error("round-tripped weak RSA-1024 should raise KMIP-001")
	}
}
