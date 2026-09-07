#include "include/BERView.h"

#if SNMP_ZERO_COPY

#include "include/BER.h"

/* ===================================================================== *
 * v3.4.0 Phase 1 — in-place SNMP message walk (zero-copy decode).       *
 * Flat, allocation-free ber_peek() loop over the UDP buffer.  Verifies  *
 * every envelope and records header fields + varbind slices.            *
 * NOTHING here mutates library state or builds responses — Phase 1 is   *
 * decode only; the owning container path remains the request path.      *
 * ===================================================================== */

/* Scoped-envelope cursor: exposes a bounded window [value, value+len)
 * for the children of an already-peeked TLV. */
struct Scope {
    const uint8_t* p = nullptr;   /* first child byte   */
    int            rem = 0;       /* bytes remaining    */
    bool           ok  = false;

    Scope() = default;

    /* From an already-peeked TLV view (p -> first child byte). */
    Scope(const BerView& v, uint8_t expectTag){
        if(v.ok && v.tag == expectTag){
            p   = v.value;
            rem = v.len;
            ok  = true;
        }
    }

    /* Peek the outermost TLV at buf (bound must INCLUDE its header). */
    Scope(const uint8_t* buf, size_t maxLen, uint8_t expectTag){
        BerView v;
        if(ber_peek(buf, maxLen, &v) && v.tag == expectTag){
            p   = v.value;
            rem = v.len;
            ok  = true;
        }
    }

    /* Peek the next child TLV at the cursor; advance on success. */
    bool next(BerView* out){
        if(!ok || rem <= 0) return false;
        if(!ber_peek(p, (size_t)rem, out)) return false;
        p   += out->totalLen;
        rem -= out->totalLen;
        return true;
    }
};

/* Decode INTEGER content (big-endian two's complement, 1..4 bytes).
 * longForm mirrors the reference decode in IntegerType::fromBuffer:
 * lengths beyond 4 bytes keep the low 32 bits.  Returns bytes consumed. */
static int ber_view_decode_integer(const uint8_t* content, int len, long* out){
    if(len <= 0) return 0;
    uint32_t v = 0;
    int n = len;
    const uint8_t* c = content;
    while(n > 0){ v = (v << 8) | *c++; n--; }
    switch(len){
        case 1: *out = (int8_t)v;  break;
        case 2: *out = (int16_t)v; break;
        case 3: if(v & 0x00800000u) v |= 0xFF000000u; *out = (int32_t)v; break;
        default: *out = (int32_t)v; break;
    }
    return len;
}

/* Decode one varbind SEQUENCE { OID, value } into out.
 * Enforces the same structural invariants as the container path:
 * exactly two children, first child an OID whose content starts with
 * the 0x2b root arc, value bounded inside the buffer. */
static bool ber_view_decode_varbind(const BerView& vbView, VarBindView* out){
    memset(out, 0, sizeof(*out));

    Scope vb(vbView, 0x30);
    if(!vb.ok) return false;

    BerView child;
    /* child 1: the OID */
    if(!vb.next(&child)) return false;
    if(child.tag != 0x06) return false;
    if(child.len <= 0) return false;              /* empty OID content: invalid */
    if(child.len > SNMP_MAX_OID_SUBIDENTIFIERS + 1) return false;
    if(child.value[0] != 0x2b) return false;      /* root arc 1.3 — same check as OIDType::fromBuffer */
    out->oid    = child.value;
    out->oidLen = (uint16_t)child.len;

    /* child 2: the value — any single TLV the buffer can bound */
    if(!vb.next(&child)) return false;
    out->value      = child.value;
    out->valueLen   = (uint16_t)child.len;
    out->valueType  = child.tag;
    out->valueTlv   = child.value - child.headerLen;
    out->valueTlvLen = (uint16_t)child.totalLen;

    /* exactly two children: nothing may remain in the varbind envelope */
    if(vb.rem != 0) return false;

    return true;
}

bool snmp_ber_peek_packet(const uint8_t* buf, size_t maxLen, SnmpHeaderView* out){
    if(!buf || !out) return false;
    memset(out, 0, sizeof(*out));
    out->version = -1;

    Scope root(buf, maxLen, 0x30);
    if(!root.ok) return false;

    BerView v;

    /* 1: INTEGER version */
    if(!root.next(&v) || v.tag != 0x02) return false;
    {
        long ver = 0;
        if(ber_view_decode_integer(v.value, v.len, &ver) != v.len) return false;
        if(ver < 0 || ver >= (long)SNMP_VERSION_MAX) return false;   /* v3-shaped / garbage reject, matches parsePacket */
        out->version = (int)ver;
    }

    /* 2: OCTET STRING community */
    if(!root.next(&v) || v.tag != 0x04) return false;
    out->community    = v.value;
    out->communityLen = (uint16_t)v.len;

    /* 3: PDU — any request PDU tag in the library's accepted range */
    if(!root.next(&v)) return false;
    if(v.tag < ASN_PDU_TYPE_MIN_VALUE || v.tag > ASN_PDU_TYPE_MAX_VALUE) return false;
    out->pduType = v.tag;

    Scope pdu(v, v.tag);
    if(!pdu.ok) return false;

    /* PDU children 1-3: request-id, error-status, error-index */
    if(!pdu.next(&v) || v.tag != 0x02) return false;
    {
        long rid = 0;
        if(ber_view_decode_integer(v.value, v.len, &rid) != v.len) return false;
        out->requestID = (snmp_request_id_t)rid;
    }

    if(!pdu.next(&v) || v.tag != 0x02) return false;
    if(ber_view_decode_integer(v.value, v.len, &out->errorStatus) != v.len) return false;

    if(!pdu.next(&v) || v.tag != 0x02) return false;
    if(ber_view_decode_integer(v.value, v.len, &out->errorIndex) != v.len) return false;

    /* 4: varbind-list SEQUENCE */
    if(!pdu.next(&v) || v.tag != 0x30) return false;

    Scope vbList(v, 0x30);
    if(!vbList.ok) return false;

    while(vbList.rem > 0){
        BerView vbView;
        if(!vbList.next(&vbView)) return false;    /* malformed sibling: hard fail (a partial trailing byte is never valid BER) */
        if(out->varbindCount < SNMP_ZC_MAX_VARBINDS){
            if(!ber_view_decode_varbind(vbView, &out->vbs[out->varbindCount])) return false;
        } else {
            out->varbindsTruncated = true;         /* walked for structure validation, slices not recorded */
        }
        out->varbindCount++;
    }

    return true;
}

#endif /* SNMP_ZERO_COPY */
