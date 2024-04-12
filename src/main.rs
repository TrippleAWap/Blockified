struct SimpleListener;

pub mod packets;
use packets::*;
use rust_raknet::*;
use std::net::{SocketAddr, ToSocketAddrs};

impl PacketListener for SimpleListener {
    fn on_packet(&self, packet: Packet) {
        match packet {
            Packet::GamePacket(packet) => {
                println!("Received game packet: {:?}", packet);
                // kill process;
                std::process::exit(0);
            }
            _ => println!("Received packet: {:?}", packet),
        }
    }
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // enable_raknet_log(1);
    let local_address = "127.0.0.1:19132".parse::<SocketAddr>().unwrap();

    let remote_address = "104.243.41.185:19132"
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();

    // create listener
    let mut listener = RaknetListener::bind(&local_address).await.unwrap();
    println!("Listening on {}", listener.local_addr().unwrap());
    listener
        .set_motd(
            "Another Minecraft Server",
            99999,
            "662",
            "1.20.71.01",
            "Survival",
            19135,
        )
        .await;
    // listen for connection;
    listener.listen().await;
    let socket: RaknetSocket = listener.accept().await.unwrap();
    println!("Accepted connection from {}", socket.peer_addr().unwrap());
    // MIM proxy to the remote_address;
    let remote_socket = RaknetSocket::connect(&remote_address).await.unwrap();

    println!("Connected to {}", remote_socket.peer_addr().unwrap());
    // catch all packets from the local socket;
    loop {
        #[allow(unused_mut)]
        let mut buffer = socket.recv().await.unwrap();
        if buffer.len() == 0 {
            continue;
        }
        println!(
            "Received {} bytes from {}",
            buffer.len(),
            socket.peer_addr().unwrap()
        );
        // log buffer ( translate to hex string )
        let hex_buffer = buffer.iter().map(|b| format!("0x{:02x}", b));
        println!("{}", hex_buffer.collect::<Vec<String>>().join(" "));
        // Forward packets to the remote socket
        remote_socket
            .send(&buffer, Reliability::ReliableOrdered)
            .await
            .unwrap();
        println!("build connection");
        loop {
            tokio::select! {
                a = socket.recv() => {
                    let a = match a{
                        Ok(p) => p,
                        Err(_) => {
                            remote_socket.close().await.unwrap();
                            break;
                        },
                    };
                    // println!("{} -> {} {:?}", "client", "server", a.iter().map(|b| format!("0x{:02x}", b)).collect::<Vec<String>>().join(" "));
                    parse_packets(&a, &SimpleListener{}).unwrap();

                    match remote_socket.send(&a, Reliability::ReliableOrdered).await{
                        Ok(p) => p,
                        Err(_) => {
                            socket.close().await.unwrap();
                            break;
                        },
                    };
                },
                b = remote_socket.recv() => {
                    let b = match b{
                        Ok(p) => p,
                        Err(_) => {
                            socket.close().await.unwrap();
                            break;
                        },
                    };
                    parse_packets(&b, &SimpleListener{}).unwrap();
                    match socket.send(&b, Reliability::ReliableOrdered).await{
                        Ok(p) => p,
                        Err(_) => {
                            remote_socket.close().await.unwrap();
                            break;
                        },
                    };
                }
            }
        }
        socket.close().await.unwrap();
        remote_socket.close().await.unwrap();
        println!("close connection");
    }
}


