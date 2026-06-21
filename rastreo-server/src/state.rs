use std::sync::Arc;

use rastreo_core::Resolver;

#[derive(Clone)]
pub struct AppState {
    pub resolver: Arc<dyn Resolver>,
}

impl AppState {
    pub fn new(resolver: Arc<dyn Resolver>) -> Self {
        Self { resolver }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rastreo_core::HickoryResolver;

    fn build_state() -> AppState {
        let resolver: Arc<dyn Resolver> =
            Arc::new(HickoryResolver::from_system().expect("system resolver"));
        AppState::new(resolver)
    }

    #[test]
    fn app_state_is_send_sync_and_clone() {
        fn assert_send_sync_clone<T: Send + Sync + Clone>() {}
        assert_send_sync_clone::<AppState>();
    }

    #[test]
    fn clone_shares_resolver_arc() {
        let state = build_state();
        let clone = state.clone();
        assert!(Arc::ptr_eq(&state.resolver, &clone.resolver));
    }
}
