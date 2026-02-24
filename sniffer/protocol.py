"""
Alephium discovery protocol wire format (UDP).
Based on alephium/protocol DiscoveryMessage and MessageSerde.
"""
import struct
import hashlib
from dataclasses import dataclass
from typing import List, Optional, Tuple

# Discovery version used by the network
CURRENT_DISCOVERY_VERSION = 1
# Payload type codes: Ping=0, Pong=1, FindNode=2, Neighbors=3
CODE_NEIGHBORS = 3
# Secp256k1 signature size
SIGNATURE_LENGTH = 64
# CliqueId = PublicKey size
CLIQUE_ID_LENGTH = 32
# Magic bytes length
MAGIC_LENGTH = 4
CHECKSUM_LENGTH = 4
LENGTH_FIELD_SIZE = 4


def djb_hash(data: bytes) -> int:
    """DJB hash (same as Alephium DjbHash.intHash)."""
    h = 5381
    for b in data:
        h = ((h << 5) + h) + (b & 0xFF)
    return h & 0xFFFFFFFF


def magic_bytes(network_id: int) -> bytes:
    """Magic bytes for discovery messages (mainnet=0, testnet=1)."""
    # Hash.hash(s"alephium-${networkId.id}").toRandomIntUnsafe -> Bytes.from(...)
    # Hash = Blake2b in Alephium
    msg = f"alephium-{network_id}".encode()
    h = hashlib.blake2b(msg, digest_size=32).digest()
    # toRandomIntUnsafe: sum of 32-bit big-endian chunks
    val = 0
    for i in range(0, 32, 4):
        val = (val + int.from_bytes(h[i : i + 4], "big")) & 0xFFFFFFFF
    return struct.pack(">I", val)


def checksum(data: bytes) -> bytes:
    return struct.pack(">I", djb_hash(data))


# --- Compact integer (Alephium CompactInteger.Signed) ---
# First 2 bits: 00=1 byte, 01=2 byte, 10=4 byte, 11=multi
MASK_REST = 0xC0
MASK_MODE = 0x3F


def decode_compact_int(data: bytes) -> Tuple[int, int]:
    """Decode a compact signed int; returns (value, bytes_consumed)."""
    if not data:
        raise ValueError("empty")
    b0 = data[0]
    mode = b0 & MASK_REST
    if mode == 0x00:  # SingleByte
        return (b0 & 0xFF, 1)
    if mode == 0x40:  # TwoByte
        if len(data) < 2:
            raise ValueError("incomplete two-byte")
        v = ((data[0] & MASK_MODE) << 8) | (data[1] & 0xFF)
        return (v, 2)
    if mode == 0x80:  # FourByte
        if len(data) < 4:
            raise ValueError("incomplete four-byte")
        v = (
            ((data[0] & MASK_MODE) << 24)
            | ((data[1] & 0xFF) << 16)
            | ((data[2] & 0xFF) << 8)
            | (data[3] & 0xFF)
        )
        return (v, 4)
    # MultiByte
    n = (b0 & MASK_MODE) + 5
    if len(data) < n:
        raise ValueError("incomplete multibyte")
    if n == 5:
        v = int.from_bytes(data[1:5], "big")
        return (v, 5)
    raise ValueError("unsupported multibyte")


def encode_compact_int(n: int) -> bytes:
    """Encode int as compact signed (for small values 0..31 single byte)."""
    if 0 <= n < 0x20:
        return bytes([n])
    if 0 <= n < 0x2000:
        return bytes([0x40 | (n >> 8), n & 0xFF])
    if 0 <= n < 0x20000000:
        return bytes(
            [
                0x80 | (n >> 24),
                (n >> 16) & 0xFF,
                (n >> 8) & 0xFF,
                n & 0xFF,
            ]
        )
    return bytes([0xC0 + 4, (n >> 24) & 0xFF, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])


def decode_length_prefixed_bytes(data: bytes) -> Tuple[bytes, int]:
    """Decode ByteString (length compact + bytes). Returns (payload, consumed)."""
    length, used = decode_compact_int(data)
    if length < 0 or used + length > len(data):
        raise ValueError("invalid length or data")
    return (data[used : used + length], used + length)


@dataclass
class BrokerInfo:
    """One peer from Neighbors (address is discovery UDP address)."""
    clique_id: bytes  # 32
    broker_id: int
    broker_num: int
    address: str  # host
    port: int


def parse_broker_info(data: bytes) -> Tuple[BrokerInfo, int]:
    """Parse one BrokerInfo: cliqueId(32) + brokerId + brokerNum + InetAddress + port."""
    if len(data) < CLIQUE_ID_LENGTH:
        raise ValueError("data too short for BrokerInfo")
    clique_id = data[:CLIQUE_ID_LENGTH]
    pos = CLIQUE_ID_LENGTH
    broker_id, n = decode_compact_int(data[pos:])
    pos += n
    broker_num, n = decode_compact_int(data[pos:])
    pos += n
    # InetSocketAddress: InetAddress (ByteString = length + bytes) + port (Int)
    addr_bytes, n = decode_length_prefixed_bytes(data[pos:])
    pos += n
    port, n = decode_compact_int(data[pos:])
    pos += n
    # InetAddress: 4 bytes IPv4 or 16 bytes IPv6
    if len(addr_bytes) == 4:
        host = ".".join(str(b) for b in addr_bytes)
    elif len(addr_bytes) == 16:
        host = ":".join(f"{int.from_bytes(addr_bytes[i:i+2], 'big'):x}" for i in range(0, 16, 2))
    else:
        host = addr_bytes.hex()
    return (BrokerInfo(clique_id=clique_id, broker_id=broker_id, broker_num=broker_num, address=host, port=port), pos)


def parse_neighbors_payload(payload: bytes) -> List[BrokerInfo]:
    """Parse Neighbors payload: compact length + BrokerInfo list."""
    count, pos = decode_compact_int(payload)
    if count < 0:
        return []
    result = []
    rest = payload[pos:]
    for _ in range(count):
        info, n = parse_broker_info(rest)
        result.append(info)
        rest = rest[n:]
    return result


def unwrap_message(raw: bytes, magic: bytes) -> Optional[bytes]:
    """
    Unwrap discovery message: check magic, checksum, length; return data (signature+header+payload).
    """
    if len(raw) < MAGIC_LENGTH + CHECKSUM_LENGTH + LENGTH_FIELD_SIZE:
        return None
    if raw[:MAGIC_LENGTH] != magic:
        return None
    checksum_received = raw[MAGIC_LENGTH : MAGIC_LENGTH + CHECKSUM_LENGTH]
    msg_length = struct.unpack(">I", raw[MAGIC_LENGTH + CHECKSUM_LENGTH : MAGIC_LENGTH + CHECKSUM_LENGTH + 4])[0]
    data_start = MAGIC_LENGTH + CHECKSUM_LENGTH + LENGTH_FIELD_SIZE
    if len(raw) < data_start + msg_length:
        return None
    data = raw[data_start : data_start + msg_length]
    if checksum(data) != checksum_received:
        return None
    return data


def parse_message_payload_type_and_rest(data: bytes) -> Tuple[int, bytes]:
    """
    data = signature(64) + header(DiscoveryVersion) + payload_type + payload_bytes.
    Returns (payload_type, payload_bytes) after header.
    """
    if len(data) < SIGNATURE_LENGTH + 1 + 1:
        raise ValueError("data too short")
    # Skip signature
    rest = data[SIGNATURE_LENGTH:]
    # Header = DiscoveryVersion (compact int, value 1 -> 1 byte)
    _, n = decode_compact_int(rest)
    rest = rest[n:]
    if not rest:
        raise ValueError("no payload type")
    # Payload type (compact int, 0-3)
    payload_type, n = decode_compact_int(rest)
    payload = rest[n:]
    return (payload_type, payload)


def get_response_payload_type(raw: bytes, network_id: int) -> Tuple[Optional[int], Optional[bytes]]:
    """Unwrap and return (payload_type, payload_bytes) or (None, None) for debugging."""
    magic = magic_bytes(network_id)
    data = unwrap_message(raw, magic)
    if not data:
        return (None, None)
    try:
        payload_type, payload = parse_message_payload_type_and_rest(data)
        return (payload_type, payload)
    except (ValueError, IndexError):
        return (None, None)


def extract_neighbors_from_message(raw: bytes, network_id: int) -> List[BrokerInfo]:
    """If raw is a Neighbors message, return list of BrokerInfo; else empty."""
    magic = magic_bytes(network_id)
    data = unwrap_message(raw, magic)
    if not data:
        return []
    try:
        payload_type, payload = parse_message_payload_type_and_rest(data)
        if payload_type != CODE_NEIGHBORS:
            return []
        return parse_neighbors_payload(payload)
    except (ValueError, IndexError):
        return []


def build_find_node_message(network_id: int, target_clique_id: bytes) -> bytes:
    """
    Build a FindNode request (no signature needed: senderCliqueId is None -> zero signature).
    target_clique_id: 32 bytes (any CliqueId, e.g. random for discovery).
    """
    magic = magic_bytes(network_id)
    # signature: 64 zero bytes
    signature = bytes(64)
    # header: discovery version 1
    header = encode_compact_int(CURRENT_DISCOVERY_VERSION)
    # payload: type 2 (FindNode) + targetId (32 bytes)
    payload_type = encode_compact_int(2)
    payload = payload_type + target_clique_id
    data = signature + header + payload
    msg_checksum = checksum(data)
    msg_length = struct.pack(">I", len(data))
    return magic + msg_checksum + msg_length + data


def build_ping_message(network_id: int, session_id: bytes) -> bytes:
    """
    Build a Ping with no senderInfo (senderCliqueId None -> zero signature).
    session_id: 32 bytes (DiscoveryMessage.Id = Hash).
    """
    magic = magic_bytes(network_id)
    signature = bytes(64)
    header = encode_compact_int(CURRENT_DISCOVERY_VERSION)
    # Ping: type 0, sessionId (32), Option[BrokerInfo] = None -> compact 0 for option
    payload_type = encode_compact_int(0)
    # Option serde: 1 byte 0 for None
    option_none = bytes([0])
    payload = payload_type + session_id + option_none
    data = signature + header + payload
    msg_checksum = checksum(data)
    msg_length = struct.pack(">I", len(data))
    return magic + msg_checksum + msg_length + data
