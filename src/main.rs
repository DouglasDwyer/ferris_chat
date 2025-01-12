#![allow(warnings)]

use enet_sys::*;
use local_ip_address::*;
use serde::*;
use std::net::*;

pub struct NatPunchthroughPacket {
    pub magic_cookie: u64,
    pub id: u64
}

impl NatPunchthroughPacket {
    pub const MAGIC_COOKIE: u64 = 2664366037301559495;

    pub fn new(local: &PeerAddressSet) -> Self {
        Self {
            magic_cookie: Self::MAGIC_COOKIE,
            id: local.id
        }
    }

    pub fn as_bytes(&self) -> [u8; size_of::<Self>()] {
        unsafe {
            *std::mem::transmute::<_, &[u8; size_of::<Self>()]>(self)
        }
    }

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        unsafe {
            if size_of::<Self>() <= data.len() {
                let packet = std::ptr::read_unaligned(data.as_ptr().cast::<Self>());
                if packet.magic_cookie == Self::MAGIC_COOKIE {
                    Some(packet)
                }
                else {
                    None
                }
            }
            else {
                None
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerAddressSet {
    pub local: SocketAddrV4,
    pub id: u64,
    pub public_ips: Vec<Ipv4Addr>,
    pub port: u16,
    pub symmetric_nat: bool,
}

impl PeerAddressSet {
    const MAX_RETRIES: usize = 10;

	const MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];

    const STUN_SERVERS: &[&str] = &[
		"stun.12voip.com:3478",
		"stun.1und1.de:3478",
		"stun.acrobits.cz:3478",
		"stun.actionvoip.com:3478",
		"stun.antisip.com:3478",
		"stun.avigora.fr:3478",
		"stun.bluesip.net:3478",
		"stun.cablenet-as.net:3478",
		"stun.callromania.ro:3478",
		"stun.cheapvoip.com:3478",
		"stun.cope.es:3478",
		"stun.counterpath.com:3478",
		"stun.counterpath.net:3478",
		"stun.dcalling.de:3478",
		"stun.dus.net:3478",
		"stun.ekiga.net:3478",
		"stun.epygi.com:3478",
		"stun.freeswitch.org:3478",
		"stun.freevoipdeal.com:3478",
		"stun.gmx.de:3478",
		"stun.gmx.net:3478",
		"stun.halonet.pl:3478",
		"stun.hoiio.com:3478",
		"stun.internetcalls.com:3478",
		"stun.intervoip.com:3478",
		"stun.ipfire.org:3478",
		"stun.ippi.fr:3478",
		"stun.ipshka.com:3478",
		"stun.it1.hr:3478",
		"stun.jumblo.com:3478",
		"stun.justvoip.com:3478",
		"stun.l.google.com:19302",
		"stun.linphone.org:3478",
		"stun.liveo.fr:3478",
		"stun.lowratevoip.com:3478",
		"stun.myvoiptraffic.com:3478",
		"stun.netappel.com:3478",
		"stun.netgsm.com.tr:3478",
		"stun.nfon.net:3478",
		"stun.nonoh.net:3478",
		"stun.ozekiphone.com:3478",
		"stun.pjsip.org:3478",
		"stun.powervoip.com:3478",
		"stun.ppdi.com:3478",
		"stun.rockenstein.de:3478",
		"stun.rolmail.net:3478",
		"stun.rynga.com:3478",
		"stun.schlund.de:3478",
		"stun.sigmavoip.com:3478",
		"stun.sip.us:3478",
		"stun.sipdiscount.com:3478",
		"stun.sipgate.net:10000",
		"stun.sipgate.net:3478",
		"stun.siplogin.de:3478",
		"stun.siptraffic.com:3478",
		"stun.smartvoip.com:3478",
		"stun.smsdiscount.com:3478",
		"stun.solcon.nl:3478",
		"stun.solnet.ch:3478",
		"stun.sonetel.com:3478",
		"stun.sonetel.net:3478",
		"stun.srce.hr:3478",
		"stun.t-online.de:3478",
		"stun.tel.lu:3478",
		"stun.telbo.com:3478",
		"stun.tng.de:3478",
		"stun.twt.it:3478",
		"stun.vo.lu:3478",
		"stun.voicetrading.com:3478",
		"stun.voip.aebc.com:3478",
		"stun.voip.blackberry.com:3478",
		"stun.voip.eutelia.it:3478",
		"stun.voipblast.com:3478",
		"stun.voipbuster.com:3478",
		"stun.voipbusterpro.com:3478",
		"stun.voipcheap.co.uk:3478",
		"stun.voipcheap.com:3478",
		"stun.voipgain.com:3478",
		"stun.voipgate.com:3478",
		"stun.voipinfocenter.com:3478",
		"stun.voipplanet.nl:3478",
		"stun.voippro.com:3478",
		"stun.voipraider.com:3478",
		"stun.voipstunt.com:3478",
		"stun.voipwise.com:3478",
		"stun.voipzoom.com:3478",
		"stun.voys.nl:3478",
		"stun.voztele.com:3478",
		"stun.webcalldirect.com:3478",
		"stun.zadarma.com:3478",
		"stun1.l.google.com:19302",
		"stun2.l.google.com:19302",
		"stun3.l.google.com:19302",
		"stun4.l.google.com:19302",
		"relay.webwormhole.io:3478",
    ];

    pub unsafe fn host_address_set(host: *mut ENetHost) -> Result<PeerAddressSet, String> {
        use std::hash::*;
        use std::net::*;

        let mut ip_addresses = Vec::new();
        let mut port = None;
        let mut symmetric_nat = false;

        let id = RandomState::new().build_hasher().finish();

        for i in 0..Self::MAX_RETRIES {            
            let random_index = id as usize % Self::STUN_SERVERS.len();
            let address = Self::STUN_SERVERS[random_index];

            let mut data = [
				0x00, 0x01, // message type
				0x00, 0x00, // message length
				Self::MAGIC_COOKIE[0], Self::MAGIC_COOKIE[1], Self::MAGIC_COOKIE[2], Self::MAGIC_COOKIE[3], // "Magic cookie"
				random_index as u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // transaction ID
            ];

            let Ok(mut addresses) = address.to_socket_addrs().map_err(err_to_string) else { continue; };
            let Some(first) = addresses.filter_map(|x| match x {
                SocketAddr::V4(socket_addr_v4) => Some(socket_addr_v4),
                SocketAddr::V6(socket_addr_v6) => None,
            }).next() else { continue; };

            let mut enet_addr = ENetAddress { host: u32::to_be(first.ip().to_bits()), port: first.port() };
            let send_res = enet_socket_send((*host).socket, &enet_addr, &ENetBuffer { data: data.as_mut_ptr().cast(), dataLength: data.len() }, 1);
            assert!(send_res as usize == data.len());
            
            let mut received = [0; 1024];
            loop {
                let mut input = _ENetSocketWait_ENET_SOCKET_WAIT_RECEIVE as u32;
                let wait_a_minute = enet_socket_wait((*host).socket, &mut input, 2000);

                let read_len = enet_socket_receive((*host).socket, &mut enet_addr, &mut ENetBuffer { data: received.as_mut_ptr().cast(), dataLength: received.len() }, 1);

                if 0 < read_len {
                    if let Ok(addrs) = Self::parse_address(&received[..read_len as usize], &data[8..20]) {
                        for addr in &addrs {
                            if !ip_addresses.contains(addr.ip()) {
                                ip_addresses.push(*addr.ip());
                            }
                            if let Some(prev_port) = port {
                                if prev_port != addr.port() {
                                    symmetric_nat = true;
                                }
                            }
                            port = Some(addr.port());
                        }
                        break;
                    }
                }
                else if read_len < 0 {
                    panic!("TIMEOUT BRUH {read_len:?}");
                }
                else {
                    break;
                }
            }
        }

        Ok(PeerAddressSet {
            local: Self::get_local_address((*host).address.port)?,
            id,
            public_ips: ip_addresses,
            port: port.unwrap_or(0),
            symmetric_nat
        })
    }

    fn get_local_address(port: u16) -> Result<SocketAddrV4, String> {
        let IpAddr::V4(local) = local_ip().map_err(err_to_string)? else { unreachable!() };
        Ok(SocketAddrV4::new(local, port))
    }

    fn parse_address(stun_response: &[u8], transaction: &[u8]) -> Result<Vec<SocketAddrV4>, String> {
        const MAPPED_ADDRESS: u16 = 0x0001;
        const XOR_MAPPED_ADDRESS: u16 = 0x0020;

        Self::parse_header(stun_response, transaction)?;

        let mut result = Vec::new();
        let mut remaining_data = &stun_response[20..];
        while !remaining_data.is_empty() {
            let ty = u16::from_be_bytes(array_slice(remaining_data, 0));
            let len = u16::from_be_bytes(array_slice(remaining_data, 2));
            remaining_data = &remaining_data[4..];

            match ty {
                XOR_MAPPED_ADDRESS | MAPPED_ADDRESS => {
                    let xor = remaining_data[0];
                    if ty == MAPPED_ADDRESS && xor != 0 {
                        return Err("Nonzero XOR value for mapped address".to_string());
                    }

                    let addr_family = remaining_data[1];
                    if addr_family == 1 {
                        let mut address_data: [u8; 6] = array_slice(remaining_data, 2);
                        if ty == XOR_MAPPED_ADDRESS {
                            for (byte, cookie) in address_data.iter_mut().zip(Self::MAGIC_COOKIE) {
                                *byte ^= cookie;
                            }
                        }

                        result.push(SocketAddrV4::new(
                            Ipv4Addr::from_bits(u32::from_be_bytes(array_slice(&address_data, 2))),
                            u16::from_be_bytes(array_slice(&address_data, 0))));

                        remaining_data = &remaining_data[(len as usize + 3) & !3..];
                    }
                    else if addr_family == 2 {
                        remaining_data = &remaining_data[(len as usize + 3) & !3..];
                    }
                    else {
                        return Err("Unknown address family".to_string());
                    }
                },
                _ => remaining_data = &remaining_data[(len as usize + 3) & !3..]
            }
        }

        Ok(result)
    }

    fn parse_header(stun_response: &[u8], transaction: &[u8]) -> Result<(), String> {
        if stun_response.len() < 20 {
            Err("Invalid header length".to_string())
        }
        else {
            if stun_response[0] != 1 || stun_response[1] != 1 {
                return Err("Invalid STUN binding".to_string());
            }
            if u16::from_be_bytes(array_slice(stun_response, 2)) as usize != stun_response.len() - 20 {
                return Err("Invalid size".to_string());
            }
            if Self::MAGIC_COOKIE != &stun_response[4..8] {
                return Err("Invalid cookie".to_string());
            }
            if transaction != &stun_response[8..20] {
                return Err("Invalid transaction ID".to_string());
            }

            Ok(())
        }
    }
}

fn under_same_nat(local: &PeerAddressSet, remote: &PeerAddressSet) -> bool {
    for first in &local.public_ips {
        for second in &remote.public_ips {
            if first == second {
                return true;
            }
        }
    }

    return false;
}

/// Utilizes NAT punchthrough to establish a firewall hole between the `local` and `remote` peers.
unsafe fn hole_punch(host: *mut ENetHost, local: &PeerAddressSet, remote: &PeerAddressSet) -> Result<SocketAddrV4, String> {
    if under_same_nat(local, remote) {
        return Ok(remote.local);
    }
    else {
        if remote.symmetric_nat {
            println!("Attempting NAT punchthrough against symmetric NAT...");
        }
        else {
            println!("Attempting NAT punchthrough against cone NAT...");
        }

        let port_expansion = if remote.symmetric_nat { 100u32.div_ceil(remote.public_ips.len() as u32) // 100 ports every 10 ms, or 1000 ports pinged a second
        } else { 0 };

        let mut port_counter = 0;
        
        let packet = NatPunchthroughPacket::new(local);
        let mut data = packet.as_bytes();

        loop {
            for remote_ip in &remote.public_ips {
                let port_incr = port_counter / 2;
                let base_port = if port_incr % 2 == 0 {
                    (port_incr / 2) * port_expansion as i32
                } else {
                    -(port_incr / 2 + 1) * port_expansion as i32
                };

                if remote.symmetric_nat {
                    println!("CHECK PORTS {} to {}", remote.port.wrapping_add(base_port as u16), remote.port.wrapping_add(base_port as u16).wrapping_add(port_expansion as u16 - 1));
                }

                for port_exp in 0..port_expansion {
                    let port = remote.port.wrapping_add(base_port as u16).wrapping_add(port_exp as u16);
                    let remote_address = ENetAddress { host: u32::to_be(remote_ip.to_bits()), port: remote.port };            
                    let send_res = enet_socket_send((*host).socket, &remote_address, &ENetBuffer { data: data.as_mut_ptr().cast(), dataLength: data.len() }, 1);
                    assert!(send_res as usize == data.len());
                }
            }

            let mut received = [0; 64];
            let mut input = _ENetSocketWait_ENET_SOCKET_WAIT_RECEIVE as u32;
            enet_socket_wait((*host).socket, &mut input, 10);  // ms

            let mut sender_addr = std::mem::zeroed();
            let read_len = enet_socket_receive((*host).socket, &mut sender_addr, &mut ENetBuffer { data: received.as_mut_ptr().cast(), dataLength: received.len() }, 1);

            if 0 < read_len {
                if let Some(punchthrough_packet) = NatPunchthroughPacket::from_bytes(&received) {
                    if punchthrough_packet.id == remote.id {
                        let ip_addr = Ipv4Addr::from_bits(u32::from_be(sender_addr.host));
                        let send_res = enet_socket_send((*host).socket, &sender_addr, &ENetBuffer { data: data.as_mut_ptr().cast(), dataLength: data.len() }, 1);
                        return Ok(SocketAddrV4::new(ip_addr, sender_addr.port));
                    }
                }
            }

            port_counter += 1;
        }
    }
}

unsafe fn connect_run_chat(host: *mut ENetHost, remote: SocketAddrV4) {
    use std::sync::*;

    let enet_addr = ENetAddress { host: u32::to_be(remote.ip().to_bits()), port: remote.port() };
    let peer = enet_host_connect(host, &enet_addr, 2, 0);
    assert!(!peer.is_null());

    let mut event = std::mem::zeroed::<ENetEvent>();
    if (enet_host_service(host, &mut event, 5000) > 0) && event.type_ == _ENetEventType_ENET_EVENT_TYPE_CONNECT {
        println!("Connected to peer at remote {remote:?}");
        let outgoing_messages = Arc::new(Mutex::new(Vec::new()));
        let outgoing_messages_clone = outgoing_messages.clone();

        std::thread::spawn(move || {
            loop {
                let mut buffer = String::new();
                std::io::stdin().read_line(&mut buffer).expect("Failed to read user input");
                outgoing_messages_clone.lock().expect("Failed to lock outgoing messages.").push(buffer.trim_end().to_owned());
            }
        });

        loop {
            if (enet_host_service(host, &mut event, 100) > 0) {
                if event.type_ == _ENetEventType_ENET_EVENT_TYPE_RECEIVE {
                    let string = std::str::from_utf8(std::slice::from_raw_parts((*event.packet).data, (*event.packet).dataLength))
                        .expect("Remote host sent invalid data.");
                    println!("Remote: {string}");
                }
                else if event.type_ == _ENetEventType_ENET_EVENT_TYPE_DISCONNECT {
                    println!("Remote host disconnected.");
                    std::process::abort();
                }
            }

            for message in outgoing_messages.lock().expect("Failed to lock outgoing messages.").drain(..) {
                let packet = enet_packet_create(message.as_bytes().as_ptr().cast(), message.as_bytes().len(), _ENetPacketFlag_ENET_PACKET_FLAG_RELIABLE as u32);
                enet_peer_send(peer, 0, packet);
            }
        }
    }
    else {
        panic!("Failed to connect to remote {remote:?}");
    }
}

fn main() {
    unsafe {
        enet_initialize();
        let address = ENetAddress { host: ENET_HOST_ANY, port: ENET_PORT_ANY as u16 };
        let server = enet_host_create(&address, 128, 2, 0, 0);
    
        if server.is_null() {
            panic!("Could not create enet host");
        }

        println!("Gathering host addresses...");
        let address_set = PeerAddressSet::host_address_set(server).expect("Failed to gather addresses.");
        let address_data = serde_json::to_string(&address_set).expect("Failed to serialize address data");
        println!("Your address token: {address_data}");
        println!("Copy/paste peer's address token:");

        let mut peer_address_data = String::new();
        std::io::stdin().read_line(&mut peer_address_data).expect("Failed to read user input.");
        let peer_address_set = serde_json::from_str(&peer_address_data).expect("Failed to parse peer addresss.");
        
        let remote_addr = hole_punch(server, &address_set, &peer_address_set).expect("Failed to punch hole");
        connect_run_chat(server, remote_addr);
    }
}

fn array_slice<T: Copy, const N: usize>(slice: &[T], start: usize) -> [T; N] {
    let result: &[T; N] = slice[start..start + N].try_into().expect("Failed to create array slice");
    *result
}

fn err_to_string(x: impl std::error::Error) -> String {
    format!("{x:?}")
}