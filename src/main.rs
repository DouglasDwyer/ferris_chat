use enet_sys::*;
use local_ip_address::*;
use std::net::*;

#[derive(Clone, Debug)]
pub struct PeerAddressSet {
    pub local: SocketAddrV4,
    pub public_ips: Vec<Ipv4Addr>,
    pub port: u16,
    pub symmetric_nat: bool
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

        let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)).expect("Failed to bind socket.");
        socket.set_read_timeout(Some(std::time::Duration::from_secs(2)));

        let mut ip_addresses = Vec::new();
        let mut port = None;
        let mut symmetric_nat = false;

        for i in 0..Self::MAX_RETRIES {            
            let random_index = RandomState::new().build_hasher().finish() as usize % Self::STUN_SERVERS.len();
            let address = Self::STUN_SERVERS[random_index];

            let mut data = [
				0x00, 0x01, // message type
				0x00, 0x00, // message length
				Self::MAGIC_COOKIE[0], Self::MAGIC_COOKIE[1], Self::MAGIC_COOKIE[2], Self::MAGIC_COOKIE[3], // "Magic cookie"
				random_index as u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // transaction ID
            ];

            socket.send_to(&data, address);

            let mut received = [0; 1024];
            if let Ok((read_len, _)) = socket.recv_from(&mut received) {
                if let Ok(addrs) = Self::parse_address(&received[..read_len], &data[8..20]) {
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
                }
            }
        }

        Ok(PeerAddressSet {
            local: Self::get_local_address((*host).address.port)?,
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

fn main() {
    unsafe {
        enet_initialize();
        let address = ENetAddress { host: ENET_HOST_ANY, port: ENET_PORT_ANY as u16 };
        let server = enet_host_create(&address, 128, 2, 0, 0);
    
        if server.is_null() {
            panic!("Could not create enet host");
        }

        println!("{:?}", PeerAddressSet::host_address_set(server));
    }
}

fn array_slice<T: Copy, const N: usize>(slice: &[T], start: usize) -> [T; N] {
    let result: &[T; N] = slice[start..start + N].try_into().expect("Failed to create array slice");
    *result
}

fn err_to_string(x: impl std::error::Error) -> String {
    format!("{x:?}")
}