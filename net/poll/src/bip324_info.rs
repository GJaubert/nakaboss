use bip324::{Handshake, PacketHandler};
use nakamoto_net::{LocalDuration, LocalTime};

/// Version content is always empty for the current version of the protocol.
pub const VERSION_CONTENT: [u8; 0] = [];
/// Number of bytes for the garbage terminator.
pub const GARBAGE_TERMINATOR_BYTES: usize = 16;
/// Number of bytes used to indicate size when decrypting a message
pub const DEFAULT_SIZE_BYTES_V2: usize = 3;
/// Size of an ElliSwift key
pub const ELLI_SWIFT_KEY_SIZE: usize = 64;
/// Maxi possible size of the buffer containing the Elliswift key
pub const MAX_GARBAGE_BUFFER_BYTES: usize = 36;
/// Duration after a P2P_V2 should fall back to V1
pub const BIP324_HANDSHAKE_TIMEOUT: LocalDuration = LocalDuration::from_secs(5);

#[derive(Default)]
pub struct Bip324Info {
    pub key_sent: Option<Vec<u8>>,
    pub key_received: Option<Vec<u8>>,
    pub terminator_sent: Option<Vec<u8>>,
    pub garbage_received: Vec<u8>,
    pub packet_handler: Option<PacketHandler>,
    pub handshake: Option<Box<Handshake<'static>>>,
    pub message_buffer: MessageBuffer,
    pub handshake_started: Option<LocalTime>,
}

#[derive(Default)]
pub struct MessageBuffer {
    pub pending_bytes: usize,
    pub buffer: Vec<u8>,
}
