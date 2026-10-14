//! Additional decision transport over the existing network snapshot.
use crate::App;
use anyhow::Result;
use guard_grpc::v1::{
    NetworkReply, NetworkRequest,
    network_server::{Network, NetworkServer},
};
pub use hangang_runtime::configuration;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};
use tokio::{net::TcpListener, sync::Semaphore};
use tonic::{Request, Response, Status, transport::ServerTlsConfig};

struct Service {
    app: App,
    requests: Arc<Semaphore>,
}
#[tonic::async_trait]
impl Network for Service {
    async fn check(
        &self,
        request: Request<NetworkRequest>,
    ) -> Result<Response<NetworkReply>, Status> {
        let mut values = request.metadata().get_all("authorization").iter();
        let supplied = values
            .next()
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        if values.next().is_some()
            || !supplied.is_some_and(|value| {
                crate::protocol::matches_token(value.as_bytes(), self.app.collector.as_bytes())
            })
        {
            return Err(Status::unauthenticated("collector credential required"));
        }
        let _permit = self
            .requests
            .clone()
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("decision capacity"))?;
        let input = request.into_inner();
        let ip = match input.ip.as_slice() {
            bytes if bytes.len() == 4 => {
                IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(bytes).unwrap()))
            }
            bytes if bytes.len() == 16 => {
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).unwrap()))
            }
            _ => return Err(Status::invalid_argument("invalid address size")),
        };
        let view = self.app.view.load();
        let decision = self.app.query(&view, ip, crate::now());
        let available = decision.revision >= input.minimum_revision;
        Ok(Response::new(NetworkReply {
            request_id: input.request_id,
            revision: decision.revision,
            verdict: if !available {
                3
            } else if decision.action == "deny" {
                2
            } else {
                1
            },
            mode: if !available {
                0
            } else if decision.mode == guard_core::Mode::Enforce {
                2
            } else {
                1
            },
            ttl_ms: if available { decision.ttl_ms as u32 } else { 0 },
        }))
    }
}
pub async fn serve(
    listener: TcpListener,
    tls: ServerTlsConfig,
    app: App,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let incoming = hangang_runtime::incoming(listener);
    hangang_runtime::server(tls)?
        .add_service(
            NetworkServer::new(Service {
                requests: Arc::new(Semaphore::new(app.max_http_requests)),
                app,
            })
            .max_decoding_message_size(2048)
            .max_encoding_message_size(1024),
        )
        .serve_with_incoming_shutdown(incoming, async move {
            if !*stop.borrow() {
                let _ = stop.changed().await;
            }
        })
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request(token: &str) -> Request<NetworkRequest> {
        let mut request = Request::new(NetworkRequest {
            request_id: 7,
            ip: vec![192, 0, 2, 1],
            minimum_revision: 0,
        });
        request
            .metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        request
    }
    #[tokio::test]
    async fn admission_is_bounded_and_revision_fence_is_unavailable() {
        let service = Service {
            app: crate::tests::app(),
            requests: Arc::new(Semaphore::new(1)),
        };
        let held = service.requests.clone().acquire_owned().await.unwrap();
        assert_eq!(
            service
                .check(request("collector-test-token"))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::ResourceExhausted
        );
        // Authentication still precedes capacity admission.
        assert_eq!(
            service
                .check(request("admin-test-token"))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );
        drop(held);
        let mut input = request("collector-test-token");
        input.get_mut().minimum_revision = u64::MAX;
        let result = service.check(input).await.unwrap().into_inner();
        assert_eq!((result.verdict, result.mode, result.ttl_ms), (3, 0, 0));
    }
}
