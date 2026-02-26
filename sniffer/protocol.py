"""
Alephium discovery protocol wire format (UDP) and TCP broker Hello (client version).
Based on alephium/protocol DiscoveryMessage and MessageSerde.

Encoding verification (vs Alephium):
- Frame: magic(4) + checksum(4) + length(4) + data (MessageSerde.unwrap order).
- Magic: Bytes.from(Hash.hash("alephium-${networkId.id}").toRandomIntUnsafe); Hash=Blake2b(32),
  toRandomIntUnsafe = sum of 8×4-byte big-endian ints; Bytes.from = 4-byte BE (NetworkConfig.scala).
- Checksum: DjbHash.intHash(data), 4-byte BE (MessageSerde.checksum).
- Length: data.length, 4-byte BE (MessageSerde.length).
- Data: signature(64) + header + payload. signature = 64 zeros when senderCliqueId is None (Ping/FindNode).
- Header: DiscoveryVersion (compact signed int, value 65536 → 4 bytes 0x80 0x01 0x00 0x00).
- Payload: intSerde(Code.toInt) ++ payload_bytes; Code: Ping=0, Pong=1, FindNode=2, Neighbors=3.
- Ping: Id(32) + Option[BrokerInfo]; Option None = 1 byte 0 (optionSerde).
- FindNode: targetId (CliqueId = PublicKey, 33 bytes).
"""
import socket
import struct
import time
import hashlib
import logging
from dataclasses import dataclass
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)

# Discovery version used by the network (Alephium CurrentDiscoveryVersion = Bytes.toIntUnsafe(ByteString(0,1,0,0)) = 65536)
CURRENT_DISCOVERY_VERSION = 65536
# Valid broker Hello clientId fallback when no reference node is available (node may ban invalid clientId).
BROKER_HELLO_CLIENT_ID_FALLBACK = "scala-alephium/v4.3.1/Linux/p2p-v2"
# Payload type codes: Ping=0, Pong=1, FindNode=2, Neighbors=3
CODE_NEIGHBORS = 3
# Secp256k1 signature size
SIGNATURE_LENGTH = 64
# CliqueId = PublicKey size (SecP256K1PublicKey = 33 bytes compressed)
CLIQUE_ID_LENGTH = 33
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
    clique_id: bytes  # 33 (SecP256K1PublicKey)
    broker_id: int
    broker_num: int
    address: str  # host
    port: int


def parse_broker_info(data: bytes) -> Tuple[BrokerInfo, int]:
    """Parse one BrokerInfo: cliqueId(33) + brokerId + brokerNum + InetAddress + port."""
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


# Payload type names for logging
_PAYLOAD_NAMES = {0: "Ping", 1: "Pong", 2: "FindNode", 3: "Neighbors"}


def describe_discovery_message(raw: bytes, network_id: int, max_hex: int = 32) -> str:
    """Return a short description for logging: e.g. 'Ping', 'Neighbors (5)', or '? 142 bytes' + hex prefix."""
    payload_type, payload = get_response_payload_type(raw, network_id)
    if payload_type is not None:
        name = _PAYLOAD_NAMES.get(payload_type, f"type{payload_type}")
        if payload_type == CODE_NEIGHBORS and payload:
            try:
                count = decode_compact_int(payload)[0]
                if count >= 0:
                    return f"{name} ({count} peers)"
            except (ValueError, IndexError):
                pass
        return name
    if not raw:
        return "empty"
    hex_prefix = raw[:max_hex].hex()
    if len(raw) > max_hex:
        hex_prefix += "..."
    return f"? {len(raw)} bytes hex={hex_prefix}"


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
    target_clique_id: 33 bytes (any CliqueId = PublicKey, e.g. random for discovery).
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


# --- TCP broker (Hello message for client version) ---
# TCP frame same as UDP: magic(4) + checksum(4) + length(4) + data.
# data = header (WireVersion, compact int) + payload (code compact int + Hello: clientId length-prefixed string + ...).


def parse_tcp_hello_client_id(data: bytes) -> Optional[str]:
    """
    Parse TCP broker message data (after unwrap) and return clientId from Hello payload if present.
    data = header (WireVersion compact int) + payload (code + clientId length + clientId bytes + ...).
    Returns None if not a Hello or parse error.
    """
    try:
        pos = 0
        _, n = decode_compact_int(data)
        pos += n
        if pos >= len(data):
            return None
        code, n = decode_compact_int(data[pos:])
        pos += n
        if code != 0:
            return None  # not Hello
        if pos >= len(data):
            return None
        size, n = decode_compact_int(data[pos:])
        pos += n
        if size < 0 or size > 256 or pos + size > len(data):
            return None
        client_id_bytes = data[pos : pos + size]
        return client_id_bytes.decode("utf-8")
    except (ValueError, UnicodeDecodeError, IndexError):
        return None


def parse_tcp_payload_code_and_payload(data: bytes) -> Tuple[int, bytes]:
    """
    Parse TCP broker message data (after unwrap).
    data = header (WireVersion compact int) + code (compact int) + payload_bytes.
    Returns (code, payload_bytes).
    """
    pos = 0
    _, n = decode_compact_int(data)
    pos += n
    if pos >= len(data):
        raise ValueError("no code")
    code, n = decode_compact_int(data[pos:])
    pos += n
    return (code, data[pos:])


# Broker payload codes (Payload.Code): Hello=0, ..., ChainState=16
CODE_HELLO = 0
CODE_CHAIN_STATE = 16
BLOCK_HASH_LENGTH = 32


def parse_chain_tip(data: bytes) -> Tuple[bytes, int, int]:
    """
    Parse one ChainTip: hash(32) + height(compact int) + weight(BigInteger = length-prefixed bytes).
    Returns (hash_bytes, height, bytes_consumed).
    """
    if len(data) < BLOCK_HASH_LENGTH:
        raise ValueError("data too short for ChainTip")
    h = data[:BLOCK_HASH_LENGTH]
    pos = BLOCK_HASH_LENGTH
    height, n = decode_compact_int(data[pos:])
    pos += n
    weight_len, n = decode_compact_int(data[pos:])
    pos += n
    if weight_len < 0 or pos + weight_len > len(data):
        raise ValueError("invalid weight length in ChainTip")
    pos += weight_len
    return (h, height, pos)


def parse_chain_state_payload(payload: bytes) -> List[Tuple[bytes, int]]:
    """
    Parse ChainState payload: AVector[ChainTip] = length (compact int) + ChainTip list.
    Returns list of (hash_bytes, height).
    """
    if not payload:
        return []
    count, pos = decode_compact_int(payload)
    if count < 0:
        return []
    tips = []
    rest = payload[pos:]
    for _ in range(count):
        h, height, n = parse_chain_tip(rest)
        tips.append((h, height))
        rest = rest[n:]
    return tips


def build_hello_message(
    network_id: int,
    client_id: str,
    clique_id: bytes,
    broker_id: int,
    broker_num: int,
    private_key_bytes: bytes,
) -> bytes:
    """
    Build broker Hello message. clique_id: 33 bytes, private_key_bytes: 32 bytes (secp256k1).
    """
    import hashlib as _hashlib
    from ecdsa import SigningKey, SECP256k1

    def _sigencode_canonical(r: int, s: int, order: int) -> bytes:
        """Encode (r, s) as 64 bytes: 32-byte r + 32-byte s, big-endian. Alephium requires s <= order/2 (low-S)."""
        half_order = order >> 1
        if s > half_order:
            s = order - s
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    if len(clique_id) != 33 or len(private_key_bytes) != 32:
        raise ValueError("clique_id must be 33 bytes, private_key 32 bytes")
    inter_broker_bytes = (
        clique_id + encode_compact_int(broker_id) + encode_compact_int(broker_num)
    )
    to_sign = _hashlib.blake2b(inter_broker_bytes, digest_size=32).digest()
    sk = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
    sig = sk.sign_digest(to_sign, sigencode=_sigencode_canonical)
    if len(sig) != 64:
        raise ValueError("expected 64-byte signature")
    ts_ms = int(time.time() * 1000)
    client_id_utf = client_id.encode("utf-8")
    # Alephium TimeStamp is 8-byte big-endian Long (Bytes.from(millis)), not compact int
    ts_bytes = struct.pack(">q", ts_ms)
    hello_payload = (
        encode_compact_int(len(client_id_utf))
        + client_id_utf
        + ts_bytes
        + inter_broker_bytes
        + sig
    )
    magic = magic_bytes(network_id)
    wire_version = 65536
    data = encode_compact_int(wire_version) + encode_compact_int(CODE_HELLO) + hello_payload
    msg_checksum = checksum(data)
    msg_length = struct.pack(">I", len(data))
    return magic + msg_checksum + msg_length + data


def _read_one_tcp_frame(sock: socket.socket, magic: bytes, timeout: float) -> Optional[bytes]:
    """Read one broker TCP frame. Returns unwrapped data or None."""
    sock.settimeout(timeout)
    header = sock.recv(12)
    if len(header) < 12:
        return None
    if header[:4] != magic:
        return None
    msg_len = int.from_bytes(header[8:12], "big")
    if msg_len <= 0 or msg_len > 0x100000:
        return None
    rest = b""
    while len(rest) < msg_len:
        chunk = sock.recv(min(8192, msg_len - len(rest)))
        if not chunk:
            return None
        rest += chunk
    raw = header + rest
    return unwrap_message(raw, magic)


def _get_client_id_from_reference_nodes(
    reference_nodes: List[Tuple[str, int]],
    reference_broker_port: Optional[int],
    network_id: int,
    timeout: float = 5.0,
) -> Optional[str]:
    """
    Connect to the first available reference node's broker, read Hello, return its clientId.
    reference_nodes: list of (host, discovery_port). reference_broker_port: broker port to use (or use discovery port per node).
    """
    for ref_host, ref_port in reference_nodes:
        port = reference_broker_port if reference_broker_port is not None else ref_port
        logger.info("Getting clientId from reference node %s:%s ...", ref_host, port)
        cid = fetch_client_version_tcp(ref_host, port, network_id, timeout)
        if cid and "/" in cid:
            logger.info("Using clientId from reference: %s", cid)
            return cid
        logger.info("Reference %s:%s did not respond or invalid clientId", ref_host, port)
    logger.info("No reference node responded; using fallback clientId")
    return None


def fetch_chain_state_tcp(
    host: str,
    discovery_port: int,
    network_id: int,
    timeout: float = 10.0,
    broker_port: Optional[int] = None,
    reference_nodes: Optional[List[Tuple[str, int]]] = None,
    reference_broker_port: Optional[int] = None,
) -> Optional[Tuple[Optional[str], bool, List[Tuple[bytes, int]]]]:
    """
    Connect to node's broker TCP, perform handshake, read ChainState.
    Uses clientId from reference_nodes (connect to one, read its Hello) so the target node accepts us.
    Falls back to BROKER_HELLO_CLIENT_ID_FALLBACK if no reference nodes or all fail.
    Returns (client_id, synced, tips) where tips = [(hash, height), ...], or None on failure.
    synced is always None from broker ChainState (cannot be derived from partial tips; use REST /infos/self-clique-synced for real synced).
    """
    hello_client_id = None
    if reference_nodes:
        hello_client_id = _get_client_id_from_reference_nodes(
            reference_nodes, reference_broker_port, network_id, min(timeout, 5.0)
        )
    if not hello_client_id:
        hello_client_id = BROKER_HELLO_CLIENT_ID_FALLBACK
        logger.info("Using fallback clientId: %s", hello_client_id)
    port = broker_port if broker_port is not None else discovery_port
    magic = magic_bytes(network_id)
    try:
        logger.info("Connecting to target %s:%s (broker) ...", host, port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        try:
            data = _read_one_tcp_frame(sock, magic, timeout)
            if not data:
                logger.warning("No data received from target (connection closed or timeout)")
                return None
            client_id = parse_tcp_hello_client_id(data)
            code, payload = parse_tcp_payload_code_and_payload(data)
            if code != CODE_HELLO:
                logger.warning("Target sent unexpected message type %s (expected Hello=0)", code)
                return None
            logger.info("Received Hello from target, clientId=%s", client_id or "(none)")
            try:
                from ecdsa import SigningKey, SECP256k1

                priv = SigningKey.generate(curve=SECP256k1)
                vk = priv.get_verifying_key()
                point = vk.pubkey.point
                x = point.x().to_bytes(32, "big")
                y_parity = int(point.y()) & 1
                pub = bytes([2 + y_parity]) + x
                hello_msg = build_hello_message(
                    network_id, hello_client_id, pub, 0, 4, priv.to_string()
                )
                sock.sendall(hello_msg)
                logger.info("Sent our Hello (clientId=%s), waiting for ChainState ...", hello_client_id)
            except Exception as e:
                logger.warning("Failed to build/send Hello: %s", e)
                return None
            tips: List[Tuple[bytes, int]] = []
            read_timeout = min(timeout, 5.0)
            deadline = time.time() + timeout
            last_log = 0.0
            while True:
                try:
                    data = _read_one_tcp_frame(sock, magic, read_timeout)
                except socket.timeout:
                    now = time.time()
                    if now >= deadline:
                        logger.warning("Timeout waiting for ChainState (node sends it on sync interval)")
                        break
                    if now - last_log >= 5.0:
                        logger.info("Still waiting for ChainState (%.0fs left) ...", deadline - now)
                        last_log = now
                    continue
                except OSError as e:
                    logger.warning("Connection closed or error while waiting for ChainState: %s", e)
                    break
                if not data:
                    now = time.time()
                    if now >= deadline:
                        logger.warning("Timeout waiting for ChainState (node sends it on sync interval)")
                        break
                    if now - last_log >= 5.0:
                        logger.info("Still waiting for ChainState (%.0fs left) ...", deadline - now)
                        last_log = now
                    continue
                try:
                    code, payload = parse_tcp_payload_code_and_payload(data)
                    if code == CODE_CHAIN_STATE:
                        tips = parse_chain_state_payload(payload)
                        logger.info("Received ChainState with %s tips", len(tips))
                        break
                    logger.info("Received message type %s (waiting for ChainState=16), continuing ...", code)
                except (ValueError, IndexError) as e:
                    logger.info("Could not parse message: %s", e)
            if not tips:
                return (client_id, None, [])
            return (client_id, None, tips)
        finally:
            try:
                sock.close()
            except OSError:
                pass
    except OSError:
        return None
    return None


def fetch_client_version_tcp(
    host: str, port: int, network_id: int, timeout: float = 5.0
) -> Optional[str]:
    """
    Connect to node's broker TCP port, read first message (expect Hello), return clientId string
    (e.g. 'scala-alephium/v3.1.1/Linux') or None. Does not send anything; server sends Hello first
    on inbound connection. Closes connection after reading one message.
    """
    magic = magic_bytes(network_id)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        try:
            header = sock.recv(12)
            if len(header) < 12:
                return None
            msg_len = int.from_bytes(header[8:12], "big")
            if msg_len <= 0 or msg_len > 0x100000:
                return None
            rest = b""
            while len(rest) < msg_len:
                chunk = sock.recv(min(8192, msg_len - len(rest)))
                if not chunk:
                    return None
                rest += chunk
            raw = header + rest
        finally:
            try:
                sock.close()
            except OSError:
                pass
        data = unwrap_message(raw, magic)
        if not data:
            return None
        return parse_tcp_hello_client_id(data)
    except OSError:
        return None


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


# Pong payload type code
CODE_PONG = 1


def ping_reply_pong(host: str, port: int, network_id: int, timeout: float = 5.0) -> bool:
    """
    Send a single UDP Ping to host:port and return True if a Pong is received.
    Blocking; run in executor if needed. Used to determine if node is online (discovery reachable).
    """
    import os as _os
    session_id = _os.urandom(32)
    msg = build_ping_message(network_id, session_id)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(msg, (host, port))
        raw, _ = sock.recvfrom(4096)
        payload_type, _ = get_response_payload_type(raw, network_id)
        return payload_type == CODE_PONG
    except (socket.timeout, OSError):
        return False
    finally:
        try:
            sock.close()
        except OSError:
            pass
