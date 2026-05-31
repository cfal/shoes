use crate::dns::fake_ip::FakeIpManager;
use hickory_resolver::proto::op::{Message, MessageType, ResponseCode};
use hickory_resolver::proto::rr::{RData, Record, RecordType};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

pub struct FakeIpServer {
    addr: SocketAddr,
    manager: Arc<FakeIpManager>,
}

impl FakeIpServer {
    pub fn new(addr: SocketAddr, manager: Arc<FakeIpManager>) -> Self {
        Self { addr, manager }
    }

    pub async fn start(&self) -> std::io::Result<()> {
        let socket = UdpSocket::bind(self.addr).await?;
        log::info!("FakeIpServer listening on UDP {}", self.addr);

        let mut buf = [0u8; 2048];
        loop {
            let (len, src) = match socket.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(e) => {
                    log::error!("FakeIpServer recv error from {}: {}", self.addr, e);
                    continue;
                }
            };

            let req_data = &buf[..len];
            let req = match Message::from_vec(req_data) {
                Ok(msg) => msg,
                Err(e) => {
                    log::warn!(
                        "FakeIpServer failed to parse DNS request from {}: {}",
                        src,
                        e
                    );
                    continue;
                }
            };

            let mut response =
                Message::new(req.metadata.id, MessageType::Response, req.metadata.op_code);
            response.metadata.recursion_desired = req.metadata.recursion_desired;
            response.metadata.recursion_available = true;

            for query in req.queries.iter() {
                response.add_query(query.clone());

                if query.query_type() == RecordType::A {
                    let domain_name = query.name().to_utf8();
                    let clean_domain = domain_name.trim_end_matches('.');

                    let fake_ip = self.manager.lookup_domain(clean_domain);

                    let record =
                        Record::from_rdata(query.name().clone(), 300, RData::A(fake_ip.into()));
                    response.add_answer(record);
                }
            }

            response.metadata.response_code = ResponseCode::NoError;

            let res_data = match response.to_vec() {
                Ok(d) => d,
                Err(e) => {
                    log::error!("FakeIpServer failed to encode DNS response: {}", e);
                    continue;
                }
            };

            if let Err(e) = socket.send_to(&res_data, src).await {
                log::error!("FakeIpServer failed to send response to {}: {}", src, e);
            }
        }
    }
}
