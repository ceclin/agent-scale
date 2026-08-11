use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    pin::Pin,
};

use iroh::dns::{BoxIter, DnsError, DnsResolver, Resolver, TxtRecordData};

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

pub(crate) fn system_resolver() -> DnsResolver {
    DnsResolver::custom(AndroidSystemResolver)
}

#[derive(Clone, Debug)]
struct AndroidSystemResolver;

impl AndroidSystemResolver {
    fn lookup(host: String) -> BoxFuture<Result<Vec<IpAddr>, DnsError>> {
        Box::pin(async move {
            let addresses = tokio::net::lookup_host((host, 0))
                .await
                .map_err(|error| n0_error::e!(DnsError::Resolve, n0_error::anyerr!(error)))?;
            Ok(addresses.map(|address| address.ip()).collect())
        })
    }
}

impl Resolver for AndroidSystemResolver {
    fn lookup_ipv4(&self, host: String) -> BoxFuture<Result<BoxIter<Ipv4Addr>, DnsError>> {
        Box::pin(async move {
            let addresses = Self::lookup(host).await?;
            let addresses: BoxIter<Ipv4Addr> = Box::new(addresses.into_iter().filter_map(|address| match address {
                IpAddr::V4(address) => Some(address),
                IpAddr::V6(_) => None,
            }));
            Ok(addresses)
        })
    }

    fn lookup_ipv6(&self, host: String) -> BoxFuture<Result<BoxIter<Ipv6Addr>, DnsError>> {
        Box::pin(async move {
            let addresses = Self::lookup(host).await?;
            let addresses: BoxIter<Ipv6Addr> = Box::new(addresses.into_iter().filter_map(|address| match address {
                IpAddr::V4(_) => None,
                IpAddr::V6(address) => Some(address),
            }));
            Ok(addresses)
        })
    }

    fn lookup_txt(&self, _host: String) -> BoxFuture<Result<BoxIter<TxtRecordData>, DnsError>> {
        // The Minimal endpoint preset uses explicit EndpointIds and Relay URLs,
        // so DNS discovery records are deliberately outside this resolver's role.
        Box::pin(async { Ok(Box::new(std::iter::empty()) as BoxIter<TxtRecordData>) })
    }

    fn clear_cache(&self) {}

    fn reset(&self) -> Box<dyn Resolver> {
        Box::new(self.clone())
    }
}
