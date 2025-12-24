import gzip
import lzma
import brotli
import cbor2
import io
from collections import deque
from typing import Dict, Any, Tuple, Optional, List, Union, Deque
from hqfbp import (
    unpack, 
    merge_headers, 
    HQFBP_CBOR_KEYS, 
    verify_and_strip_crc,
    ENCODING_REGISTRY,
    COAP_CONTENT_FORMATS,
    RS_RE,
    rs_decode
)
import re

CHUNK_RE = re.compile(r"chunk\((\d+)\)")

class PDUEvent:
    def __init__(self, header: Dict[int, Any], payload: bytes):
        self.header = header
        self.payload = payload

    def __repr__(self):
        return f"PDUEvent(header={self.header}, payload_len={len(self.payload)})"

class MessageEvent:
    def __init__(self, header: Dict[int, Any], payload: bytes):
        self.header = header
        self.payload = payload

    def __repr__(self):
        return f"MessageEvent(header={self.header}, payload_len={len(self.payload)})"

class Deframer:
    """
    Sans-I/O Deframer for HQFBP.
    Handles PDU reception, multi-sender reassembly, and announcement-based decoding.
    """

    def __init__(self):
        self._events: Deque[Union[PDUEvent, MessageEvent]] = deque()
        # Mapping (src_callsign, original_msg_id) -> {chunk_id: payload, 'headers': [header1, ...]}
        self._sessions: Dict[Tuple[Optional[str], int], Dict[str, Any]] = {}
        # Mapping (src_callsign, upcoming_msg_id) -> encodings
        self._announcements: Dict[Tuple[Optional[str], int], List[Union[int, str]]] = {}

    def receive_bytes(self, data: bytes):
        """Accept raw PDU bytes and process them into events."""
        # 1. Try to peek into the header to get src/msg_id
        try:
            peek_header, _ = unpack(data)
            header_unpacked_directly = True
        except Exception:
            header_unpacked_directly = False

        header = None
        payload = None
        encodings = None
        src_callsign = None
        msg_id = None

        if header_unpacked_directly:
            src_callsign = peek_header.get(HQFBP_CBOR_KEYS["Src-Callsign"])
            msg_id = peek_header.get(HQFBP_CBOR_KEYS["Message-Id"])
            if msg_id is not None:
                encodings = self._announcements.get((src_callsign, msg_id))
                if encodings:
                    # Strip based on announcement info
                    try:
                        data = self._strip_post_boundary_encodings(data, encodings)
                        header, payload = unpack(data)
                    except Exception:
                        return # Inconsistent
                else:
                    # Strip based on header info if present
                    encodings = peek_header.get(HQFBP_CBOR_KEYS["Content-Encoding"])
                    header, payload = peek_header, _
                    if encodings:
                        payload = self._strip_post_boundary_encodings(payload, encodings)
        else:
            # 2. Heuristic: Try unique sequences from announcements
            # We must try the sequences as they were stored (could be [h, gzip] or [gzip])
            sequences = list(set(tuple(e) if isinstance(e, list) else (e,) 
                                for e in self._announcements.values() if e is not None))
            
            for seq_tuple in sequences:
                seq = list(seq_tuple)
                try:
                    # We try to treat seq as a Content-Encoding list and strip post-boundary
                    stripped_data = self._strip_post_boundary_encodings(data, seq)
                    header, payload = unpack(stripped_data)
                    src_callsign = header.get(HQFBP_CBOR_KEYS["Src-Callsign"])
                    msg_id = header.get(HQFBP_CBOR_KEYS["Message-Id"])
                    if msg_id is not None:
                        data = stripped_data
                        encodings = seq
                        break
                except Exception:
                    continue

        if header is None or msg_id is None:
            return

        # 4. Handle Announcement
        content_type = header.get(HQFBP_CBOR_KEYS["Content-Type"])
        content_format = header.get(HQFBP_CBOR_KEYS["Content-Format"])
        
        is_announcement = (
            (content_type is not None and content_type == "application/vnd.hqfbp+cbor") or 
            (content_format is not None and content_format == COAP_CONTENT_FORMATS.get("application/vnd.hqfbp+cbor"))
        )

        if is_announcement:
            self._handle_announcement(src_callsign, payload)
            # Announcement PDUs are also events (though usually empty/minimal)
            self._events.append(PDUEvent(header, payload))
            return

        self._events.append(PDUEvent(header, payload))

        # 5. Handle Reassembly
        orig_msg_id = header.get(HQFBP_CBOR_KEYS["Original-Message-Id"], msg_id)
        session_key = (src_callsign, orig_msg_id)
        
        total_chunks = header.get(HQFBP_CBOR_KEYS["Total-Chunks"], 1)
        chunk_id = header.get(HQFBP_CBOR_KEYS["Chunk-Id"], 0)
        
        if session_key not in self._sessions:
            self._sessions[session_key] = {
                'chunks': {},
                'headers': [],
                'total_chunks': total_chunks
            }
        
        session = self._sessions[session_key]
        session['chunks'][chunk_id] = payload
        session['headers'].append(header)

        # 6. Check for Completion
        if len(session['chunks']) == session['total_chunks']:
            self._complete_message(session_key)
            # Cleanup announcement
            self._announcements.pop((src_callsign, msg_id), None)
            # And also potentially the Original-Message-Id association if any
            if orig_msg_id != msg_id:
                self._announcements.pop((src_callsign, orig_msg_id), None)

    def next_event(self) -> Optional[Union[PDUEvent, MessageEvent]]:
        """Return the next available event, or None if queue is empty."""
        return self._events.popleft() if self._events else None

    def _handle_announcement(self, src_callsign: Optional[str], payload: bytes):
        """Parse announcement payload and store encoding info."""
        try:
            ann_data = cbor2.loads(payload)
            upcoming_msg_id = ann_data.get(HQFBP_CBOR_KEYS["Message-Id"])
            upcoming_encodings = ann_data.get(HQFBP_CBOR_KEYS["Content-Encoding"])
            if upcoming_msg_id is not None:
                self._announcements[(src_callsign, upcoming_msg_id)] = upcoming_encodings
        except Exception:
            pass

    def _strip_post_boundary_encodings(self, data: bytes, encodings: Union[int, str, List[Union[int, str]]]) -> bytes:
        """Strip encodings found after the 'h' boundary."""
        if encodings is None:
            return data

        post_encs = []
        if isinstance(encodings, list):
            try:
                idx = encodings.index(-1)
                post_encs = encodings[idx + 1:]
            except ValueError:
                # No boundary marker: all are pre-boundary
                post_encs = []
        else:
            # Single value in Content-Encoding header is ALWAYS pre-boundary (content)
            # EXCEPT if it's a known integrity check like CRC that we decide to 
            # allow as a shorthand (though not strictly in RFC for CE field).
            # But wait, if this is called by the heuristic, 'encodings' might be 
            # just the post-boundary part we stored. 
            pass

        # Apply in reverse order (LIFO)
        for enc in reversed(post_encs):
            if enc in (1, "gzip"):
                data = gzip.decompress(data)
            elif enc in (3, "br"):
                data = brotli.decompress(data)
            elif enc in (4, "lzma"):
                data = lzma.decompress(data)
            elif enc in (5, 6, "crc16", "crc32"):
                data = verify_and_strip_crc(data, enc)
            elif isinstance(enc, str):
                if CHUNK_RE.match(enc):
                    continue
                m = RS_RE.match(enc)
                if m:
                    n, k = map(int, m.groups())
                    data = rs_decode(data, n, k)
        return data


    def _complete_message(self, session_key: Tuple[Optional[str], int]):
        """Assemble chunks, merge headers, and dekrunk pre-boundary encodings."""
        session = self._sessions.pop(session_key)
        
        # Concatenate chunks in order
        full_payload = b"".join(session['chunks'][i] for i in range(session['total_chunks']))
        
        # Merge headers
        merged_header = merge_headers(session['headers'])
        
        # Apply pre-boundary decodings
        encodings = merged_header.get(HQFBP_CBOR_KEYS["Content-Encoding"])
        if encodings:
            full_payload = self._apply_pre_boundary_decodings(full_payload, encodings)

        self._events.append(MessageEvent(merged_header, full_payload))

    def _apply_pre_boundary_decodings(self, data: bytes, encodings: Union[int, str, List[Union[int, str]]]) -> bytes:
        """Decompress/decode data based on pre-boundary encodings."""
        pre_encs = []
        if isinstance(encodings, (int, str)):
            pre_encs = [encodings]
        elif isinstance(encodings, list):
            try:
                idx = encodings.index(-1)
                pre_encs = encodings[:idx]
            except ValueError:
                pre_encs = encodings

        # Apply in reverse order (LIFO)
        for enc in reversed(pre_encs):
            if enc in (1, "gzip"):
                data = gzip.decompress(data)
            elif enc in (3, "br"):
                data = brotli.decompress(data)
            elif enc in (4, "lzma"):
                data = lzma.decompress(data)
            elif isinstance(enc, str):
                if CHUNK_RE.match(enc):
                    continue
                m = RS_RE.match(enc)
                if m:
                    n, k = map(int, m.groups())
                    data = rs_decode(data, n, k)
            # identity or unknown just pass through
        return data
