#ifndef BERView_h
#define BERView_h

/* ===================================================================== *
 * v3.4.0 Phase 1 — ZERO-COPY BER VIEW WALK (plan-UDP-BER-parse.md)      *
 * --------------------------------------------------------------------- *
 * Non-owning TLV inspection over the UDP packet buffer.  A BerView      *
 * points INTO the caller's buffer; it never copies and never allocates. *
 * Slices are valid only for the current request tick — never stored.    *
 *                                                                       *
 * Phase 1 scope (decode only): snmp_ber_peek_packet() validates the     *
 * full message structure and records header fields + varbind slices.    *
 * Responses are still built by the owning container path; dispatch on   *
 * slices arrives in Phase 2.  Compile-time gate: SNMP_ZERO_COPY.        *
 * ===================================================================== */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "defs.h"

#if SNMP_ZERO_COPY

/* One decoded TLV: tag byte + pointer to the first content byte + lengths.
 * ~16 B, stack-only.  totalLen = headerLen + len (the full TLV size). */
struct BerView {
    uint8_t        tag;
    const uint8_t* value;
    int            len;
    int            headerLen;
    int            totalLen;
    bool           ok;
};

/* Decode the BER length field at buf[0] (short + long form).
 * Returns bytes consumed by the length field (>=1), or 0 on malformed
 * input: indefinite form (0x80), length-byte count exceeding the buffer,
 * or >4 length bytes (content cannot fit the packet budget).
 * STRICTER than decode_ber_length_integer() (which trusts numBytes) —
 * the view walk must never read past the buffer. */
static inline int ber_decode_length(const uint8_t* buf, size_t maxLen, int* outLen){
    if(buf[0] < 0x80){
        *outLen = buf[0];
        return 1;
    }
    int numBytes = buf[0] & 0x7F;
    if(numBytes == 0)               return 0;   /* indefinite form: rejected */
    if((size_t)numBytes >= maxLen)  return 0;   /* length field runs off buffer */
    if(numBytes > 4)                return 0;   /* >2^32-1 content bytes */
    int L = 0;
    for(int k = 1; k <= numBytes; k++) L = (L << 8) | buf[k];
    *outLen = L;
    return numBytes + 1;
}

/* Peek one TLV at buf (bounded by maxLen) without consuming/copying it.
 * On success out->value points at the content inside the caller's buffer. */
static inline bool ber_peek(const uint8_t* buf, size_t maxLen, BerView* out){
    out->ok = false;
    if(!buf || !out) return false;
    if(maxLen < 2) return false;
    int contentLen = 0;
    int used = ber_decode_length(buf + 1, maxLen - 1, &contentLen);
    if(used == 0 || contentLen < 0) return false;
    size_t total = (size_t)used + 1 + (size_t)contentLen;   /* tag + length field + content */
    if(total > maxLen) return false;
    out->tag       = buf[0];
    out->value     = buf + 1 + used;
    out->len       = contentLen;
    out->headerLen = used + 1;
    out->totalLen  = (int)total;
    out->ok        = true;
    return true;
}

/* One varbind's slices (Phase 2 dispatch consumes these).  All pointers
 * reference the packet buffer and die with the request tick. */
struct VarBindView {
    const uint8_t* oid;        /* encoded OID content (dataPtr[0] == 0x2b) */
    uint16_t       oidLen;
    const uint8_t* value;      /* encoded value content (tag in valueType) */
    uint16_t       valueLen;
    uint8_t        valueType;
    const uint8_t* valueTlv;    /* original value TLV start, for canonical decode */
    uint16_t       valueTlvLen;
};

/* Result of the full in-place message walk (Phase 1 decoder output). */
struct SnmpHeaderView {
    int          version;
    const uint8_t* community;
    uint16_t     communityLen;
    uint8_t      pduType;
    snmp_request_id_t requestID;
    long         errorStatus;
    long         errorIndex;
    int          varbindCount;         /* exact wire count */
    bool         varbindsTruncated;    /* wire count > SNMP_ZC_MAX_VARBINDS */
    VarBindView  vbs[SNMP_ZC_MAX_VARBINDS];
};

/* Walk one complete SNMP message in place.  Validates every envelope
 * (root SEQUENCE, version, community, PDU, request-id/error-status/
 * error-index, varbind list, each varbind) with strict bounds checks and
 * records the header fields + per-varbind slices into out.  No allocation,
 * no copies, no library state touched.  Returns false on any structural
 * violation (malformed BER, bad version, truncated buffer).  Slices remain
 * valid only while the caller's buffer does. */
bool snmp_ber_peek_packet(const uint8_t* buf, size_t maxLen, SnmpHeaderView* out);

/* =====================================================================
 * v3.4.0 Phase 3 — BerWriter: direct-to-buffer BER serialization.
 * ---------------------------------------------------------------------
 * Writes TLVs sequentially into the outgoing UDP buffer through a cursor.
 * The EXACT running length replaces the container path's worst-case
 * arithmetic, so the packet-budget fit invariant (v3.3.2) upgrades from
 * "guaranteed conservative" to "measured": tooBig is answered only when
 * genuinely true, and a response the old math would have rejected may now
 * fit.  Every put*() is bounds-checked; a failed put marks the writer
 * failed (sticky) and returns false — callers check once at the end.
 * Encodings are byte-identical to the BER_CONTAINER::serialise() forms
 * (pinned by the Phase 3 host equivalence tests), including the INTEGER
 * always-4-byte wire form.
 * ===================================================================== */

class BerWriter {
  public:
    BerWriter(uint8_t* buf, size_t cap): base(buf), cap(cap), pos(0), failed(false) {}

    bool ok()  const { return !failed; }
    bool full() const { return failed; }
    size_t length() const { return pos; }          /* bytes written so far (exact) */

    /* --- low-level primitives --- */
    bool putByte(uint8_t b){
        if(failed) return false;
        if(pos + 1 > cap){ failed = true; return false; }
        base[pos++] = b;
        return true;
    }
    bool putBytes(const uint8_t* d, size_t n){
        if(failed) return false;
        if(pos + n > cap){ failed = true; return false; }
        memcpy(base + pos, d, n);
        pos += n;
        return true;
    }
    bool putTLVHeader(uint8_t tag, size_t contentLen){
        if(!putByte(tag)) return false;
        if(contentLen < 0x80) return putByte((uint8_t)contentLen);
        if(contentLen < 0x100){
            return putByte(0x81) && putByte((uint8_t)contentLen);
        }
        if(contentLen < 0x10000){
            return putByte(0x82) && putByte((uint8_t)(contentLen >> 8)) &&
                   putByte((uint8_t)(contentLen & 0xFF));
        }
        failed = true;
        return false;
    }
    /* Raw TLV from caller-supplied content.  ATOMIC: the full TLV must fit
     * or nothing is written (no partial headers left in the buffer). */
    bool putTLV(uint8_t tag, const uint8_t* content, size_t len){
        if(failed) return false;
        size_t headerLen = 2 + (len >= 0x100) + (len >= 0x10000);  /* tag + short/0x81/0x82 */
        if(pos + headerLen + len > cap){ failed = true; return false; }
        return putTLVHeader(tag, len) && putBytes(content, len);
    }
    /* Verbatim re-emission of a decoded TLV (request OID echo etc.). */
    bool putTLVView(const BerView& v){
        if(!v.ok){ failed = true; return false; }
        return putBytes(v.value - v.headerLen, (size_t)v.totalLen);
    }

    /* --- typed writers (byte-identical to container serialise forms) ---
     * NOTE on string/OID content: putOctets/putOIDContent write exactly the
     * bytes given.  The CONTAINER ctors clamp strings to SNMP_MAX_STRING_LEN
     * at construction; the writer deliberately has no policy — the caller
     * (Phase 4 response builder) serves handler values already clamped by
     * their callbacks, and request-slice echoes are wire lengths verbatim. */
    bool putInteger(long v){
        /* INTEGER always serialises as tag + length 4 + 4 big-endian bytes
         * (BEREncode.cpp IntegerType::serialise), never minimal-length. */
        if(!putTLVHeader(0x02, 4)) return false;
        if(!putByte((uint8_t)(v >> 24))) return false;
        if(!putByte((uint8_t)(v >> 16))) return false;
        if(!putByte((uint8_t)(v >> 8)))  return false;
        return putByte((uint8_t)v);
    }
    bool putNull(uint8_t tag){
        return putTLVHeader(tag, 0);
    }
    bool putOctets(uint8_t tag, const uint8_t* d, size_t len){
        return putTLV(tag, d, len);
    }
    /* Encoded OID: content is already base-128 wire bytes (slice or
     * handler encodedData()), first byte 0x2b. */
    bool putOIDContent(const uint8_t* encoded, size_t len){
        return putTLV(0x06, encoded, len);
    }

    /* --- scoped envelopes: reserve the header, backfill the length --- */
    struct Marker { size_t pos; uint8_t tag; size_t headerLen; };

    bool beginScope(uint8_t tag, Marker* m){
        if(failed) return false;
        m->pos = pos;
        m->tag = tag;
        /* worst-case header reservation: tag + 0x82 + 2 length bytes */
        if(pos + 4 > cap){ failed = true; return false; }
        base[pos++] = tag;
        base[pos++] = 0x82;      /* placeholder; backfilled below */
        base[pos++] = 0;         /* (fixed 3-byte header: simplifies backfill) */
        base[pos++] = 0;
        m->headerLen = 4;
        return true;
    }
    bool endScope(Marker* m){
        if(failed) return false;
        size_t contentLen = pos - m->pos - m->headerLen;
        /* encode_ber_length_integer form: <128 -> short; <256 -> 0x81 1B;
         * else 0x82 2B.  The reserved window is exactly 3 length bytes, so
         * any of these fit without shifting; shorter encodings pad by
         * memmoving the content left. */
        size_t lenBytes;
        if(contentLen < 0x80){
            base[m->pos + 1] = (uint8_t)contentLen;
            lenBytes = 1;
        } else if(contentLen < 0x100){
            base[m->pos + 1] = 0x81;
            base[m->pos + 2] = (uint8_t)contentLen;
            lenBytes = 2;
        } else {
            base[m->pos + 1] = 0x82;
            base[m->pos + 2] = (uint8_t)(contentLen >> 8);
            base[m->pos + 3] = (uint8_t)(contentLen & 0xFF);
            lenBytes = 3;
        }
        if(lenBytes < m->headerLen - 1){
            memmove(base + m->pos + 1 + lenBytes, base + m->pos + m->headerLen, contentLen);
            pos -= (m->headerLen - 1 - lenBytes);
        }
        return true;
    }

  private:
    uint8_t* base;
    size_t   cap;
    size_t   pos;
    bool     failed;
};

#endif /* SNMP_ZERO_COPY */
#endif /* BERView_h */
