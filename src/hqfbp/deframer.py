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
    rs_decode,
    RQ_RE,
    rq_decode,
    CHUNK_RE
)
import re


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
        if header_unpacked_directly and isinstance(peek_header, dict):
            src_callsign = peek_header.get(HQFBP_CBOR_KEYS["Src-Callsign"])
            msg_id = peek_header.get(HQFBP_CBOR_KEYS["Message-Id"])
            msg_id = peek_header.get(HQFBP_CBOR_KEYS["Original-Message-Id"], msg_id)
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
                        try:
                            # Strip post-boundary encodings from the FULL data
                            # because post-boundary encodings (like CRC) cover the header too.
                            data = self._strip_post_boundary_encodings(data, encodings)
                            header, payload = unpack(data)
                        except Exception:
                            return # Inconsistent
        else:
            # 2. Heuristic: Try unique sequences from announcements
            for announcement_encodings in self._announcements.values():
                if announcement_encodings is not None:
                    try:
                        data = self._strip_post_boundary_encodings(data, announcement_encodings)
                        header, payload = unpack(data)
                        src_callsign = header.get(HQFBP_CBOR_KEYS["Src-Callsign"])
                        msg_id = header.get(HQFBP_CBOR_KEYS["Message-Id"])
                        if msg_id is not None:
                            data = data
                            encodings = announcement_encodings
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
            # Apply pre-boundary decodings to the announcement payload itself
            ann_encs = header.get(HQFBP_CBOR_KEYS["Content-Encoding"])
            if ann_encs:
                payload = self._apply_pre_boundary_decodings(payload, ann_encs)
            
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

    def _apply_decoding_list(self, data: bytes, encodings: List[Union[int, str]]) -> bytes:
        """Apply a list of decodings in reverse order (LIFO)."""
        for enc in reversed(encodings):
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
                else:
                    m = RQ_RE.match(enc)
                    if m:
                        mtu, repair_count = map(int, m.groups())
                        data = rq_decode(data, mtu, repair_count)
        return data

    def _strip_post_boundary_encodings(self, data: bytes, encodings: Union[int, str, List[Union[int, str]]]) -> bytes:
        """Strip encodings found after the 'h' boundary."""
        if encodings is None:
            return data

        post_encs = []
        if isinstance(encodings, list):
            try:
                boundary_idx = None
                if "h" in encodings:
                    boundary_idx = encodings.index("h")
                elif -1 in encodings:
                    boundary_idx = encodings.index(-1)
                if boundary_idx is not None:
                    post_encs = encodings[boundary_idx + 1:]
            except ValueError:
                # No boundary marker: all are pre-boundary
                post_encs = []
        else:
            # Single value in Content-Encoding header is ALWAYS pre-boundary (content)
            pass

        return self._apply_decoding_list(data, post_encs)


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
                if -1 in encodings:
                    idx = encodings.index(-1)
                else:
                    idx = encodings.index("h")
                pre_encs = encodings[:idx]
            except ValueError:
                pre_encs = encodings

        return self._apply_decoding_list(data, pre_encs)
