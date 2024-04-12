// the current way im checking the packet id's is probably bad but I'm pretty new to rustlang ( If you wanna fix it fix it )

// TODO: Fix the way we check the packet id's ( I have no idea how to do this in a better way )

// TODO: add version support for the packets
// TODO: Fix game packet parsing;
// TODO: Add more game packets;

#[derive(Debug)]
pub enum Packet {
    GamePacket(GamePacket),
    UnconnectedPing(UnconnectedPing),
    UnconnectedPong(UnconnectedPong),
    ConnectedPing(ConnectedPing),
    ConnectedPong(ConnectedPong),
    OpenConnectionRequest1(OpenConnectionRequest1),
    OpenConnectionReply1(OpenConnectionReply1),
    OpenConnectionRequest2(OpenConnectionRequest2),
    OpenConnectionReply2(OpenConnectionReply2),
    ConnectionRequest(ConnectionRequest),
    ConnectionRequestAccepted(ConnectionRequestAccepted),
    NewIncomingConnection(NewIncomingConnection),
    RaknetDisconnect(RaknetDisconnect),
    IncompatibleProtocolVersion(IncompatibleProtocolVersion),
    FrameSet(FrameSet),
    NACK(NACK),
    ACK(ACK),
    Unknown(Unknown),
}

#[derive(Debug)]
pub struct UnconnectedPing {
    // time ( long );
    pub time: i64,
    // magic ( magic );
    pub magic: i64,
    // client_guid ( long );
    pub client_guid: i64,
}

#[derive(Debug)]
pub struct UnconnectedPong {
    pub time: i64,
    pub server_guid: i64,
    pub magic: i64,
    pub server_id: String,
}

#[derive(Debug)]
pub struct ConnectedPing {
    pub time: i64,
}

#[derive(Debug)]
pub struct ConnectedPong {
    pub ping_time: i64,
    pub pong_time: i64,
}

#[derive(Debug)]
pub struct OpenConnectionRequest1 {
    pub magic: i64,
    // protocol_version ( byte );
    pub protocol_version: i8,
    // mtu ( zero padding );
    pub mtu: i16,
}

#[derive(Debug)]
pub struct OpenConnectionReply1 {
    pub magic: i64,
    pub server_guid: i64,
    pub use_security: bool,
    pub mtu: i16,
}

#[derive(Debug)]
pub struct OpenConnectionRequest2 {
    pub magic: i64,
    pub server_address: String,
    pub mtu: i16,
    pub client_guid: i64,
}

#[derive(Debug)]
pub struct OpenConnectionReply2 {
    pub magic: i64,
    pub server_guid: i64,
    pub client_address: String,
    pub mtu: i16,
    pub encryption_enabled: bool,
}

#[derive(Debug)]
pub struct ConnectionRequest {
    pub guid: i64,
    pub time: i64,
    pub use_security: bool,
}

#[derive(Debug)]
pub struct ConnectionRequestAccepted {
    pub client_address: String,
    pub system_index: i8,
    pub system_addresses: Vec<String>,
    pub request_time: i64,
    pub time: i64,
}

#[derive(Debug)]
pub struct NewIncomingConnection {
    pub server_address: String,
    pub system_addresses: Vec<String>,
    pub incoming_timestamp: i64,
    pub server_timestamp: i64,
}

#[derive(Debug)]
pub struct RaknetDisconnect {
    pub reason: i32,
}

#[derive(Debug)]
pub struct IncompatibleProtocolVersion {
    // protocol_version ( byte );
    pub protocol_version: i8,
    pub magic: i64,
    pub server_guid: i64,
}

#[derive(Debug)]
pub struct FrameSet {
    pub sequence_number: u32,
    pub frames: Vec<Frame>,
}

#[derive(Debug)]
pub struct Frame {
    pub flags: u8,
    pub length: u16,
    pub reliable_frame_index: u32,
    pub sequenced_frame_index: u32,
    pub order: u32,
    pub order_channel: u8,
    pub fragment: Fragment,
}

#[derive(Debug)]
pub struct Fragment {
    pub compound_size: i32,
    pub compound_id: i16,
    pub index: i32,
    pub body: Vec<u8>,
}

#[derive(Debug)]
pub struct Game {
    pub body: Vec<u8>,
}
/**
 * NACK
Packet ID 	Field Name 	Field Type 	Notes
0xa0 	Record count 	short
Record 	Single Sequence number? 	boolean 	False for range, True for no range
No Range 	Sequence number 	uint24le 	Number of sequence to not acknowledge
Range 	Start Sequence number 	uint24le
End Sequence number 	uint24le
ACK
Packet ID 	Field Name 	Field Type 	Notes
0xc0 	Record count 	short
Record 	Single Sequence number? 	boolean 	False for range, True for no range
No Range 	Sequence number 	uint24le 	Number of sequenc
 */
#[derive(Debug)]
pub struct NACK {
    pub record_count: i16,
    pub records: Vec<NACKRecord>,
}

#[derive(Debug)]
pub struct NACKRecord {
    pub single_sequence_number: bool,
    pub sequence_number: u32,
    pub start_sequence_number: u32,
    pub end_sequence_number: u32,
}

#[derive(Debug)]
pub struct ACK {
    pub record_count: i16,
    pub records: Vec<ACKRecord>,
}

#[derive(Debug)]
pub struct ACKRecord {
    pub single_sequence_number: bool,
    pub sequence_number: u32,
    pub start_sequence_number: u32,
    pub end_sequence_number: u32,
}

#[derive(Debug)]
pub enum GamePacket {
    Login(Login),
    PlayStatus(PlayStatus),
    ServerToClientHandshake(ServerToClientHandshake),
    Disconnect(Disconnect),
    ResourcePacksInfo(ResourcePacksInfo),
    ResourcePackStack(ResourcePackStack),
    ResourcePackClientResponse(ResourcePackClientResponse),
    Text(Text),
    Unknown(Unknown),
}

#[derive(Debug)]
pub struct Login {
    pub protocol_version: i32, // Protocol version (Big Endian!)
    pub tokens: LoginTokens,
}

#[derive(Debug)]
pub struct PlayStatus {
    pub status: i32,
}

#[derive(Debug)]
pub struct ServerToClientHandshake {
    pub token: i64, // Token
}

#[derive(Debug)]
pub struct Disconnect {
    pub hide_disconnect_screen: bool, // Hide disconnect screen
    pub message: String,              // Message
}

#[derive(Debug)]
pub struct ResourcePacksInfo {
    pub must_accept: bool,                           // Must accept
    pub behaviour_packs: Vec<ResourcePackInfoEntry>, // Behaviour packs
    pub resource_packs: Vec<ResourcePackInfoEntry>,  // Resource packs
}

#[derive(Debug)]
pub struct ResourcePackStack {
    pub behaviour_packs: Vec<ResourcePackStackEntry>, // Behaviour packs
    pub resource_packs: Vec<ResourcePackStackEntry>,  // Resource packs
}

#[derive(Debug)]
pub struct ResourcePackClientResponse {
    pub status: i32,                     // Status
    pub resource_pack_ids: Vec<String>,  // Resource pack ids
    pub behaviour_pack_ids: Vec<String>, // Behaviour pack ids
}

#[derive(Debug)]
pub struct Text {
    pub type_: i32,               // Type
    pub name: String,             // Name
    pub xuid: String,             // XUID
    pub platform_chat_id: String, // Platform chat id
    pub message: String,          // Message
    pub parameters: Vec<String>,  // Parameters
}

#[derive(Debug)]
pub struct ResourcePackInfoEntry {
    pub id: String,               // Id
    pub version: String,          // Version
    pub size: i64,                // Size
    pub content_key: String,      // Content key
    pub sub_pack_name: String,    // Sub pack name
    pub content_id: String,       // Content id
    pub has_scripts: bool,        // Has scripts
    pub raytracing_capable: bool, // Raytracing capable
}

#[derive(Debug)]
pub struct ResourcePackStackEntry {
    pub id: String,            // Id
    pub version: String,       // Version
    pub sub_pack_name: String, // Sub pack name
    pub content_id: String,    // Content id
}

#[derive(Debug)]
pub struct LoginTokens {
    pub chain: Vec<String>, // Chain
}

#[derive(Debug)]
pub struct Unknown {
    pub id: u8,
    pub data: Vec<u8>,
    pub full_data: Vec<u8>,
}

pub trait PacketListener {
    fn on_packet(&self, packet: Packet);
}

pub fn parse_packets(buffer: &[u8], listener: &dyn PacketListener) -> Result<(), String> {
    let packet_id = &buffer[0];
    let packet_data = &buffer[1..];
    match packet_id {
        0x01 | 0x02 => {
            let time = i64::from_le_bytes(packet_data[0..8].try_into().unwrap());
            let magic = i64::from_le_bytes(packet_data[8..16].try_into().unwrap());
            let client_guid = i64::from_le_bytes(packet_data[16..24].try_into().unwrap());
            listener.on_packet(Packet::UnconnectedPing(UnconnectedPing {
                time,
                magic,
                client_guid,
            }));
        }
        0x1c => {
            // unconnected pong
            let time = i64::from_le_bytes(packet_data[0..8].try_into().unwrap());
            let server_guid = i64::from_le_bytes(packet_data[8..16].try_into().unwrap());
            let magic = i64::from_le_bytes(packet_data[16..24].try_into().unwrap());
            let server_id = String::from_utf8(packet_data[24..].to_vec()).unwrap();
            listener.on_packet(Packet::UnconnectedPong(UnconnectedPong {
                time,
                server_guid,
                magic,
                server_id,
            }));
        }
        0x00 => {
            // Connected Ping
            let time = i64::from_le_bytes(packet_data[0..8].try_into().unwrap());
            listener.on_packet(Packet::ConnectedPing(ConnectedPing { time }));
        }
        0x03 => {
            // Connected Pong
            let ping_time = i64::from_le_bytes(packet_data[0..8].try_into().unwrap());
            let pong_time = i64::from_le_bytes(packet_data[8..16].try_into().unwrap());
            listener.on_packet(Packet::ConnectedPong(ConnectedPong {
                ping_time,
                pong_time,
            }));
        }
        0x05 => {
            // open connection request 1
            let magic = i64::from_le_bytes(packet_data[0..8].try_into().unwrap());
            let protocol_version = i8::from_le_bytes(packet_data[8..9].try_into().unwrap());
            let mtu = i16::from_le_bytes(packet_data[9..11].try_into().unwrap());
            listener.on_packet(Packet::OpenConnectionRequest1(OpenConnectionRequest1 {
                magic,
                protocol_version,
                mtu,
            }));
        }
        0x06 => {
            // open connection reply 1
            let magic = i64::from_le_bytes(packet_data[0..8].try_into().unwrap());
            let server_guid = i64::from_le_bytes(packet_data[8..16].try_into().unwrap());
            let use_security = packet_data[16] == 0x01;
            let mtu = i16::from_le_bytes(packet_data[17..19].try_into().unwrap());
            listener.on_packet(Packet::OpenConnectionReply1(OpenConnectionReply1 {
                magic,
                server_guid,
                use_security,
                mtu,
            }));
        }
        0x07 => {
            // open connection request 2
            let magic = i64::from_le_bytes(packet_data[0..8].try_into().unwrap());
            let server_address = String::from_utf8(packet_data[8..24].to_vec()).unwrap();
            let mtu = i16::from_le_bytes(packet_data[24..26].try_into().unwrap());
            let client_guid = i64::from_le_bytes(packet_data[26..34].try_into().unwrap());
            listener.on_packet(Packet::OpenConnectionRequest2(OpenConnectionRequest2 {
                magic,
                server_address,
                mtu,
                client_guid,
            }));
        }
        0x08 => {
            // open connection reply 2
            let magic = i64::from_le_bytes(packet_data[0..8].try_into().unwrap());
            let server_guid = i64::from_le_bytes(packet_data[8..16].try_into().unwrap());
            let client_address = String::from_utf8(packet_data[16..32].to_vec()).unwrap();
            let mtu = i16::from_le_bytes(packet_data[32..34].try_into().unwrap());
            let encryption_enabled = packet_data[34] == 0x01;
            listener.on_packet(Packet::OpenConnectionReply2(OpenConnectionReply2 {
                magic,
                server_guid,
                client_address,
                mtu,
                encryption_enabled,
            }));
        }
        0x09 => {
            // connection request
            let guid = i64::from_le_bytes(packet_data[0..8].try_into().unwrap());
            let time = i64::from_le_bytes(packet_data[8..16].try_into().unwrap());
            let use_security = packet_data[16] == 0x01;
            listener.on_packet(Packet::ConnectionRequest(ConnectionRequest {
                guid,
                time,
                use_security,
            }));
        }
        0x10 => {
            // connection request accepted
            let client_address = String::from_utf8(packet_data[0..16].to_vec()).unwrap();
            let system_index = i8::from_le_bytes(packet_data[16..17].try_into().unwrap());
            let system_addresses = packet_data[17..]
                .chunks(16)
                .map(|x| String::from_utf8(x.to_vec()).unwrap())
                .collect();
            let request_time = i64::from_le_bytes(packet_data[17..25].try_into().unwrap());
            let time = i64::from_le_bytes(packet_data[25..33].try_into().unwrap());
            listener.on_packet(Packet::ConnectionRequestAccepted(
                ConnectionRequestAccepted {
                    client_address,
                    system_index,
                    system_addresses,
                    request_time,
                    time,
                },
            ));
        }
        0x13 => {
            // new incoming connection
            let server_address = String::from_utf8(packet_data[0..16].to_vec()).unwrap();
            let system_addresses = packet_data[16..]
                .chunks(16)
                .map(|x| String::from_utf8(x.to_vec()).unwrap())
                .collect();
            let incoming_timestamp = i64::from_le_bytes(packet_data[16..24].try_into().unwrap());
            let server_timestamp = i64::from_le_bytes(packet_data[24..32].try_into().unwrap());
            listener.on_packet(Packet::NewIncomingConnection(NewIncomingConnection {
                server_address,
                system_addresses,
                incoming_timestamp,
                server_timestamp,
            }));
        }
        0x15 => {
            // raknet disconnect
            let reason = i32::from_le_bytes(packet_data[0..4].try_into().unwrap());
            listener.on_packet(Packet::RaknetDisconnect(RaknetDisconnect { reason }));
        }
        0x19 => {
            // incompatible protocol version
            let protocol_version = i8::from_le_bytes(packet_data[0..1].try_into().unwrap());
            let magic = i64::from_le_bytes(packet_data[1..9].try_into().unwrap());
            let server_guid = i64::from_le_bytes(packet_data[9..17].try_into().unwrap());
            listener.on_packet(Packet::IncompatibleProtocolVersion(
                IncompatibleProtocolVersion {
                    protocol_version,
                    magic,
                    server_guid,
                },
            ));
        }
        // 0x80 -> 0x8d
        0x80..=0x8d => {
            let sequence_number = u32::from_le_bytes(packet_data[0..4].try_into().unwrap());
            let frames = packet_data[4..]
                .chunks(4)
                .map(|x| {
                    let flags = x[0];
                    let length = u16::from_le_bytes(x[1..3].try_into().unwrap());
                    let reliable_frame_index = u32::from_le_bytes(x[3..7].try_into().unwrap());
                    let sequenced_frame_index = u32::from_le_bytes(x[7..11].try_into().unwrap());
                    let order = u32::from_le_bytes(x[11..15].try_into().unwrap());
                    let order_channel = x[15];
                    let fragment = Fragment {
                        compound_size: i32::from_le_bytes(x[16..20].try_into().unwrap()),
                        compound_id: i16::from_le_bytes(x[20..22].try_into().unwrap()),
                        index: i32::from_le_bytes(x[22..26].try_into().unwrap()),
                        body: x[26..].to_vec(),
                    };
                    Frame {
                        flags,
                        length,
                        reliable_frame_index,
                        sequenced_frame_index,
                        order,
                        order_channel,
                        fragment,
                    }
                })
                .collect();
            listener.on_packet(Packet::FrameSet(FrameSet {
                sequence_number,
                frames,
            }));
        }
        0xfe => {
            // game
            parse_game_packets(packet_data, listener)?;
        }
        0xa0 => {
            // nack
            let record_count = i16::from_le_bytes(packet_data[0..2].try_into().unwrap());
            let records = packet_data[2..]
                .chunks(4)
                .map(|x| {
                    let single_sequence_number = x[0] == 0x01;
                    let sequence_number = u32::from_le_bytes(x[1..4].try_into().unwrap());
                    let start_sequence_number = u32::from_le_bytes(x[1..4].try_into().unwrap());
                    let end_sequence_number = u32::from_le_bytes(x[1..4].try_into().unwrap());
                    NACKRecord {
                        single_sequence_number,
                        sequence_number,
                        start_sequence_number,
                        end_sequence_number,
                    }
                })
                .collect::<Vec<NACKRecord>>();
            listener.on_packet(Packet::NACK(NACK {
                record_count,
                records,
            }));
        }

        _ => {
            listener.on_packet(Packet::Unknown(Unknown {
                id: *packet_id,
                data: packet_data.to_vec(),
                full_data: buffer.to_vec(),
            }));
        }
    }

    Ok(())
}

fn parse_game_packets(buffer: &[u8], listener: &dyn PacketListener) -> Result<(), String> {
    // <https://mojang.github.io/bedrock-protocol-docs/html/packetHeader.html>
    // The first 10 value bits are the packet id, the next 2 value bits are the Sender SubClientID, and the next 2 value bits are the Target SubClientID
    let packet_id = buffer[0] & 0b00111111;
    // this data should most likely be decompressed using <https://crates.io/crates/cloudflare-zlib> ( dont know if this alternative is just an alternative or has increased performance over zlib )
    let packet_data = &buffer[1..];
    match packet_id {
        0x01 => {
            // login
            let protocol_version = i32::from_le_bytes(packet_data[0..4].try_into().unwrap());
            let tokens = LoginTokens {
                chain: packet_data[4..]
                    .chunks(16)
                    .map(|x| String::from_utf8(x.to_vec()).unwrap())
                    .collect(),
            };
            listener.on_packet(Packet::GamePacket(GamePacket::Login(Login {
                protocol_version,
                tokens,
            })));
        }
        0x02 => {
            // play status
            let status = i32::from_le_bytes(packet_data[0..4].try_into().unwrap());
            listener.on_packet(Packet::GamePacket(GamePacket::PlayStatus(PlayStatus {
                status,
            })));
        }
        0x03 => {
            // server to client handshake
            let token = i64::from_le_bytes(packet_data[0..8].try_into().unwrap());
            listener.on_packet(Packet::GamePacket(GamePacket::ServerToClientHandshake(
                ServerToClientHandshake { token },
            )));
        }
        0x04 => {
            // disconnect
            let hide_disconnect_screen = packet_data[0] == 0x01;
            let message = String::from_utf8(packet_data[1..].to_vec()).unwrap();
            listener.on_packet(Packet::GamePacket(GamePacket::Disconnect(Disconnect {
                hide_disconnect_screen,
                message,
            })));
        }
        0x05 => {
            // resource packs info
            let must_accept = packet_data[0] == 0x01;
            let behaviour_packs: Vec<ResourcePackInfoEntry> = packet_data[1..]
                .chunks(32)
                .map(|x| {
                    let id = String::from_utf8(x[0..16].to_vec()).unwrap();
                    let version = String::from_utf8(x[16..32].to_vec()).unwrap();
                    let size = i64::from_le_bytes(x[32..40].try_into().unwrap());
                    let content_key = String::from_utf8(x[40..56].to_vec()).unwrap();
                    let sub_pack_name = String::from_utf8(x[56..72].to_vec()).unwrap();
                    let content_id = String::from_utf8(x[72..88].to_vec()).unwrap();
                    let has_scripts = x[88] == 0x01;
                    let raytracing_capable = x[89] == 0x01;
                    ResourcePackInfoEntry {
                        id,
                        version,
                        size,
                        content_key,
                        sub_pack_name,
                        content_id,
                        has_scripts,
                        raytracing_capable,
                    }
                })
                .collect();
            let resource_packs = packet_data[behaviour_packs.len() * 32 + 1..]
                .chunks(32)
                .map(|x| {
                    let id = String::from_utf8(x[0..16].to_vec()).unwrap();
                    let version = String::from_utf8(x[16..32].to_vec()).unwrap();
                    let size = i64::from_le_bytes(x[32..40].try_into().unwrap());
                    let content_key = String::from_utf8(x[40..56].to_vec()).unwrap();
                    let sub_pack_name = String::from_utf8(x[56..72].to_vec()).unwrap();
                    let content_id = String::from_utf8(x[72..88].to_vec()).unwrap();
                    let has_scripts = x[88] == 0x01;
                    let raytracing_capable = x[89] == 0x01;
                    ResourcePackInfoEntry {
                        id,
                        version,
                        size,
                        content_key,
                        sub_pack_name,
                        content_id,
                        has_scripts,
                        raytracing_capable,
                    }
                })
                .collect();
            listener.on_packet(Packet::GamePacket(GamePacket::ResourcePacksInfo(
                ResourcePacksInfo {
                    must_accept,
                    behaviour_packs,
                    resource_packs,
                },
            )));
        }
        _ => {
            listener.on_packet(Packet::GamePacket(GamePacket::Unknown(Unknown {
                id: packet_id,
                data: packet_data.to_vec(),
                full_data: buffer.to_vec(),
            })));
        }
    }
    Ok(())
}
