//! Monotonic domain-to-IP resolver: resolves authorized domains every
//! 60s (configurable), accumulates the union of all IPs ever seen, and
//! never drops an IP mid-engagement.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;

#[async_trait]
pub trait DnsResolver: Send + Sync {
    async fn resolve(&self, domain: &str) -> Vec<IpAddr>;
}

pub struct MonotonicResolver<R: DnsResolver> {
    pub inner: R,
    seen: Arc<RwLock<HashSet<IpAddr>>>,
}

impl<R: DnsResolver> MonotonicResolver<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            seen: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    pub async fn refresh(&self, domains: &[String]) -> HashSet<IpAddr> {
        for d in domains {
            let ips = self.inner.resolve(d).await;
            let mut s = self.seen.write().await;
            for ip in ips {
                s.insert(ip);
            }
        }
        self.snapshot().await
    }

    pub async fn snapshot(&self) -> HashSet<IpAddr> {
        self.seen.read().await.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct MockResolver {
        answers: Mutex<HashMap<String, Vec<IpAddr>>>,
    }

    #[async_trait]
    impl DnsResolver for MockResolver {
        async fn resolve(&self, domain: &str) -> Vec<IpAddr> {
            self.answers
                .lock()
                .unwrap()
                .get(domain)
                .cloned()
                .unwrap_or_default()
        }
    }

    #[tokio::test]
    async fn new_ips_accumulate() {
        let answers = Mutex::new(HashMap::from([(
            "x".to_owned(),
            vec!["1.1.1.1".parse().unwrap()],
        )]));
        let mock = MockResolver { answers };
        let resolver = MonotonicResolver::new(mock);

        resolver.refresh(&["x".into()]).await;
        let first = resolver.snapshot().await;
        assert!(first.contains(&"1.1.1.1".parse().unwrap()));
    }

    #[tokio::test]
    async fn removed_ip_remains_allowed() {
        let initial = HashMap::from([(
            "x".to_owned(),
            vec!["1.1.1.1".parse().unwrap()],
        )]);
        let mock = MockResolver {
            answers: Mutex::new(initial),
        };
        let resolver = MonotonicResolver::new(mock);
        resolver.refresh(&["x".into()]).await;
        // Simulate DNS changing.
        resolver
            .inner
            .answers
            .lock()
            .unwrap()
            .insert("x".into(), vec!["2.2.2.2".parse().unwrap()]);
        resolver.refresh(&["x".into()]).await;
        let snap = resolver.snapshot().await;
        assert!(
            snap.contains(&"1.1.1.1".parse().unwrap()),
            "old IP must be retained (monotonic)"
        );
        assert!(
            snap.contains(&"2.2.2.2".parse().unwrap()),
            "new IP must be added"
        );
    }
}
