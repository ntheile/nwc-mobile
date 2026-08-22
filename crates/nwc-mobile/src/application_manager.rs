use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::{
    ApplicationConnectionMetadata, ApplicationRegistrationBegin, ApplicationRegistrationCompletion,
    ApplicationRegistrationCoordinator, ApplicationRegistrationPass, ApplicationRevocation,
    ApplicationWorkflowError, ApprovedApplicationConnection, ClientSecretStore,
    ConnectionPresentation, CreatedWalletConnection, MobileServiceError, NwaApprovalSelection,
    NwaCallbackBegin, NwaCallbackCompletion, NwaCallbackCoordinator, NwaRequestPresentation,
    NwcMobileService, UnixTimestamp, WalletConnectionRequest,
};

/// Stable database name shared by a mobile application's foreground and background processes.
pub const NWC_MOBILE_DATABASE_FILE: &str = "nwc-mobile.sqlite3";

/// Minimum delay used when a durable retry timestamp is already due.
pub const MINIMUM_REGISTRATION_RETRY_DELAY: Duration = Duration::from_secs(5);

/// Result of preparing one application-owned wake-registration worker pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RegistrationStart {
    /// Another worker pass already owns process-local execution.
    Busy,
    /// Durable desired state is ready for one worker pass.
    Ready,
}

/// An approved NWA connection paired with the native callback action it requires.
#[derive(Debug)]
pub struct ApprovedNwaApplication {
    connection: ApprovedApplicationConnection,
    callback: NwaCallbackBegin,
}

impl ApprovedNwaApplication {
    /// Returns the atomically persisted connection approval.
    #[must_use]
    pub const fn connection(&self) -> &ApprovedApplicationConnection {
        &self.connection
    }

    /// Returns the bounded native callback action selected by the shared workflow.
    #[must_use]
    pub const fn callback(&self) -> &NwaCallbackBegin {
        &self.callback
    }

    /// Splits this result into its durable connection and native callback action.
    #[must_use]
    pub fn into_parts(self) -> (ApprovedApplicationConnection, NwaCallbackBegin) {
        (self.connection, self.callback)
    }
}

/// Batteries-included application façade over NWC lifecycle and process-local coordination.
///
/// Mobile wallets should keep one instance in their Rust application actor. The manager owns the
/// authoritative service, NWA callback lifecycle, and registration serialization so native hosts
/// only translate typed outcomes into navigation and platform capability calls.
pub struct NwcApplicationManager {
    service: NwcMobileService,
    nwa_callback: NwaCallbackCoordinator,
    registration: ApplicationRegistrationCoordinator,
}

impl NwcApplicationManager {
    /// Returns the authoritative ledger path inside a platform app-group or application directory.
    #[must_use]
    pub fn database_path(data_directory: impl AsRef<Path>) -> PathBuf {
        data_directory.as_ref().join(NWC_MOBILE_DATABASE_FILE)
    }

    /// Opens the shared application ledger using the stable mobile database name.
    pub fn open(data_directory: impl AsRef<Path>) -> Result<Self, MobileServiceError> {
        let service = NwcMobileService::open(Self::database_path(data_directory))?;
        Ok(Self::from_service(service))
    }

    /// Wraps an existing service and initializes empty process-local coordination state.
    #[must_use]
    pub fn from_service(service: NwcMobileService) -> Self {
        Self {
            service,
            nwa_callback: NwaCallbackCoordinator::default(),
            registration: ApplicationRegistrationCoordinator::default(),
        }
    }

    /// Returns the authoritative service for engine adapters that need direct ledger access.
    #[must_use]
    pub const fn service(&self) -> &NwcMobileService {
        &self.service
    }

    /// Lists complete non-sensitive connection presentations in stable creation order.
    pub fn connections(&self) -> Result<Vec<ConnectionPresentation>, MobileServiceError> {
        self.service.connection_presentations()
    }

    /// Persists non-sensitive display metadata and initializes capability-publication work.
    pub fn set_connection_metadata(
        &self,
        connection_id: &str,
        metadata: ApplicationConnectionMetadata,
    ) -> Result<(), MobileServiceError> {
        self.service
            .set_connection_metadata(connection_id, metadata)
    }

    /// Acknowledges one successfully published capability event.
    pub fn acknowledge_nwc_info_event(
        &self,
        connection_id: &str,
        relay_url: &str,
    ) -> Result<(), MobileServiceError> {
        self.service
            .acknowledge_nwc_info_event(connection_id, relay_url)
    }

    /// Parses and retains exactly one NWA request for user review.
    pub fn open_nwa_request(
        &self,
        uri: &str,
    ) -> Result<NwaRequestPresentation, MobileServiceError> {
        self.service.open_nwa_request(uri)
    }

    /// Returns the currently retained NWA request, when one exists.
    pub fn pending_nwa_request(
        &self,
    ) -> Result<Option<NwaRequestPresentation>, MobileServiceError> {
        self.service.pending_nwa_request()
    }

    /// Approves the retained NWA request and starts its validated callback lifecycle atomically
    /// from the application's perspective.
    pub fn approve_nwa(
        &mut self,
        selection: NwaApprovalSelection,
    ) -> Result<ApprovedNwaApplication, ApplicationWorkflowError> {
        let connection = self.service.approve_application_nwa(selection)?;
        let callback = self
            .nwa_callback
            .begin(connection.approval().callback_url().map(str::to_owned));
        Ok(ApprovedNwaApplication {
            connection,
            callback,
        })
    }

    /// Returns a validated callback URL while an explicit retry remains available.
    #[must_use]
    pub fn retry_nwa_callback(&self) -> Option<String> {
        self.nwa_callback.retry_url()
    }

    /// Applies the result of the platform URL-open capability.
    pub fn complete_nwa_callback(&mut self, opened: bool) -> NwaCallbackCompletion {
        self.nwa_callback.complete_open(opened)
    }

    /// Cancels the retained request and clears any process-local callback state.
    pub fn cancel_nwa(&mut self) -> Result<(), MobileServiceError> {
        self.service.clear_pending_nwa()?;
        self.nwa_callback.clear();
        Ok(())
    }

    /// Creates a wallet-managed, exportable NWC connection.
    pub fn create_connection(
        &self,
        request: WalletConnectionRequest,
        secrets: &dyn ClientSecretStore,
    ) -> Result<CreatedWalletConnection, ApplicationWorkflowError> {
        self.service.create_wallet_connection(request, secrets)
    }

    /// Exports an existing wallet-managed connection without exposing its secret to durable state.
    pub fn export_connection_uri(
        &self,
        connection_id: &str,
        lud16: Option<String>,
        secrets: &dyn ClientSecretStore,
    ) -> Result<String, ApplicationWorkflowError> {
        self.service
            .export_wallet_connection_uri(connection_id, lud16, secrets)
    }

    /// Permanently revokes a connection and deletes wallet-managed client secret material.
    pub fn revoke_connection(
        &self,
        connection_id: &str,
        secrets: &dyn ClientSecretStore,
    ) -> Result<ApplicationRevocation, ApplicationWorkflowError> {
        self.service
            .revoke_application_connection(connection_id, secrets)
    }

    /// Marks desired registration state for durable refresh before another worker pass.
    pub fn mark_registration_refresh_pending(&mut self) {
        self.registration.mark_refresh_pending();
    }

    /// Refreshes desired durable registration state when necessary and claims one worker pass.
    pub fn begin_registration(
        &mut self,
        enabled: bool,
    ) -> Result<RegistrationStart, MobileServiceError> {
        match self.registration.begin() {
            ApplicationRegistrationBegin::Busy => Ok(RegistrationStart::Busy),
            ApplicationRegistrationBegin::Ready => Ok(RegistrationStart::Ready),
            ApplicationRegistrationBegin::RefreshRequired => {
                self.service.refresh_wake_registrations(enabled)?;
                self.registration.complete_refresh();
                match self.registration.begin() {
                    ApplicationRegistrationBegin::Ready => Ok(RegistrationStart::Ready),
                    ApplicationRegistrationBegin::Busy
                    | ApplicationRegistrationBegin::RefreshRequired => Ok(RegistrationStart::Busy),
                }
            }
        }
    }

    /// Completes one claimed registration pass and selects the next application action.
    pub fn finish_registration(
        &mut self,
        pass: ApplicationRegistrationPass,
        now: UnixTimestamp,
    ) -> ApplicationRegistrationCompletion {
        self.registration.finish(pass, now.as_secs())
    }

    /// Invalidates older retry timers and returns the token for a new timer.
    pub fn schedule_registration_retry(&mut self) -> u64 {
        self.registration.schedule_retry()
    }

    /// Returns whether a retry timer still represents the latest requested attempt.
    #[must_use]
    pub const fn registration_retry_is_current(&self, token: u64) -> bool {
        self.registration.retry_is_current(token)
    }

    /// Clears process-local callback and registration coordination for a reset wallet session.
    pub fn reset_session(&mut self) {
        self.nwa_callback.clear();
        self.registration.reset();
    }
}

impl std::fmt::Debug for NwcApplicationManager {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("NwcApplicationManager { .. }")
    }
}

/// Computes a bounded registration retry delay from an absolute durable timestamp.
#[must_use]
pub fn registration_retry_delay(next_attempt_at: u64, now: UnixTimestamp) -> Duration {
    Duration::from_secs(
        next_attempt_at
            .saturating_sub(now.as_secs())
            .max(MINIMUM_REGISTRATION_RETRY_DELAY.as_secs()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_path_is_stable_and_scoped_to_the_host_directory() {
        assert_eq!(
            NwcApplicationManager::database_path("/tmp/example"),
            PathBuf::from("/tmp/example").join(NWC_MOBILE_DATABASE_FILE)
        );
    }

    #[test]
    fn retry_delay_never_spins_when_durable_time_is_due() {
        assert_eq!(
            registration_retry_delay(99, UnixTimestamp::from_secs(100)),
            MINIMUM_REGISTRATION_RETRY_DELAY
        );
        assert_eq!(
            registration_retry_delay(110, UnixTimestamp::from_secs(100)),
            Duration::from_secs(10)
        );
    }
}
