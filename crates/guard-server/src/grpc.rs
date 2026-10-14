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
        let view = self.app.view.load_full();
        let geo = view.requires_geo().then(|| self.app.geo.load_full());
        let decision = match &geo {
            Some(geo) => view.query_ip_context(ip, crate::now(), geo.context(ip)),
            None => view.query_ip(ip, crate::now()),
        };
        Ok(Response::new(self.reply(
            input.request_id,
            input.minimum_revision,
            &view,
            geo.as_ref(),
            decision,
        )))
    }
}
impl Service {
    fn reply(
        &self,
        request_id: u64,
        minimum_revision: u64,
        view: &Arc<guard_core::DecisionView>,
        geo: Option<&Arc<crate::geoip::GeoCatalog>>,
        decision: guard_core::DecisionRef<'_>,
    ) -> NetworkReply {
        let available = decision.revision >= minimum_revision
            && Arc::ptr_eq(view, &self.app.view.load_full())
            && geo.is_none_or(|captured| Arc::ptr_eq(captured, &self.app.geo.load_full()));
        NetworkReply {
            request_id,
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
            ttl_ms: if available {
                decision.ttl_ms.min(5000) as u32
            } else {
                0
            },
        }
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
    #[test]
    fn changed_owner_with_same_revision_discards_captured_network_reply() {
        let service = Service {
            app: crate::tests::app(),
            requests: Arc::new(Semaphore::new(1)),
        };
        let view = service.app.view.load_full();
        let decision = view.query_ip("192.0.2.1".parse().unwrap(), crate::now());
        assert_ne!(service.reply(7, 0, &view, None, decision).verdict, 3);
        service.app.view.store(Arc::new((*view).clone()));
        let decision = view.query_ip("192.0.2.1".parse().unwrap(), crate::now());
        let reply = service.reply(7, 0, &view, None, decision);
        assert_eq!((reply.request_id, reply.revision), (7, view.revision));
        assert_eq!((reply.verdict, reply.mode, reply.ttl_ms), (3, 0, 0));
    }
    #[test]
    fn changed_geo_owner_discards_reply_that_used_captured_geo() {
        let service = Service {
            app: crate::tests::app(),
            requests: Arc::new(Semaphore::new(1)),
        };
        let view = service.app.view.load_full();
        let geo = service.app.geo.load_full();
        let decision = view.query_ip_context(
            "192.0.2.1".parse().unwrap(),
            crate::now(),
            geo.context("192.0.2.1".parse().unwrap()),
        );
        assert_ne!(service.reply(8, 0, &view, Some(&geo), decision).verdict, 3);
        service
            .app
            .geo
            .store(Arc::new(crate::geoip::GeoCatalog::default()));
        let decision = view.query_ip_context(
            "192.0.2.1".parse().unwrap(),
            crate::now(),
            geo.context("192.0.2.1".parse().unwrap()),
        );
        let reply = service.reply(8, 0, &view, Some(&geo), decision);
        assert_eq!((reply.verdict, reply.mode, reply.ttl_ms), (3, 0, 0));
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
