// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use anyhow::Context as _;
use async_graphql::{Context, Description, Enum, ID, InputObject, Json, Object, SimpleObject};
use mas_storage::{
    queue::{
        DeactivateUserJob, ProvisionUserJob, QueueJobRepositoryExt as _,
        SendAccountRecoveryEmailsJob, SendEmailAuthenticationCodeJob,
    },
    user::UserRepository,
};
use tracing::{info, warn};
use ulid::Ulid;
use url::Url;
use zeroize::Zeroizing;

use super::verify_password_if_needed;
use crate::graphql::{
    UserId,
    model::{NodeType, User},
    state::ContextExt,
};

#[derive(Default)]
pub struct UserMutations {
    _private: (),
}

/// The input for the `addUser` mutation.
#[derive(InputObject)]
struct AddUserInput {
    /// The username of the user to add.
    username: String,

    /// Skip checking with the homeserver whether the username is valid.
    ///
    /// Use this with caution! The main reason to use this, is when a user used
    /// by an application service needs to exist in MAS to craft special
    /// tokens (like with admin access) for them
    skip_homeserver_check: Option<bool>,
}

/// The status of the `addUser` mutation.
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
enum AddUserStatus {
    /// The user was added.
    Added,

    /// The user already exists.
    Exists,

    /// The username is reserved.
    Reserved,

    /// The username is invalid.
    Invalid,
}

/// The payload for the `addUser` mutation.
#[derive(Description)]
enum AddUserPayload {
    Added(mas_data_model::User),
    Exists(mas_data_model::User),
    Reserved,
    Invalid,
}

#[Object(use_type_description)]
impl AddUserPayload {
    /// Status of the operation
    async fn status(&self) -> AddUserStatus {
        match self {
            Self::Added(_) => AddUserStatus::Added,
            Self::Exists(_) => AddUserStatus::Exists,
            Self::Reserved => AddUserStatus::Reserved,
            Self::Invalid => AddUserStatus::Invalid,
        }
    }

    /// The user that was added.
    async fn user(&self) -> Option<User> {
        match self {
            Self::Added(user) | Self::Exists(user) => Some(User(user.clone())),
            Self::Invalid | Self::Reserved => None,
        }
    }
}

/// The input for the `lockUser` mutation.
#[derive(InputObject)]
struct LockUserInput {
    /// The ID of the user to lock.
    user_id: ID,

    /// Permanently lock the user.
    deactivate: Option<bool>,
}

/// The status of the `lockUser` mutation.
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
enum LockUserStatus {
    /// The user was locked.
    Locked,

    /// The user was not found.
    NotFound,
}

/// The payload for the `lockUser` mutation.
#[derive(Description)]
enum LockUserPayload {
    /// The user was locked.
    Locked(mas_data_model::User),

    /// The user was not found.
    NotFound,
}

#[Object(use_type_description)]
impl LockUserPayload {
    /// Status of the operation
    async fn status(&self) -> LockUserStatus {
        match self {
            Self::Locked(_) => LockUserStatus::Locked,
            Self::NotFound => LockUserStatus::NotFound,
        }
    }

    /// The user that was locked.
    async fn user(&self) -> Option<User> {
        match self {
            Self::Locked(user) => Some(User(user.clone())),
            Self::NotFound => None,
        }
    }
}

/// The input for the `unlockUser` mutation.
#[derive(InputObject)]
struct UnlockUserInput {
    /// The ID of the user to unlock
    user_id: ID,
}

/// The status of the `unlockUser` mutation.
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
enum UnlockUserStatus {
    /// The user was unlocked.
    Unlocked,

    /// The user was not found.
    NotFound,
}

/// The payload for the `unlockUser` mutation.
#[derive(Description)]
enum UnlockUserPayload {
    /// The user was unlocked.
    Unlocked(mas_data_model::User),

    /// The user was not found.
    NotFound,
}

#[Object(use_type_description)]
impl UnlockUserPayload {
    /// Status of the operation
    async fn status(&self) -> UnlockUserStatus {
        match self {
            Self::Unlocked(_) => UnlockUserStatus::Unlocked,
            Self::NotFound => UnlockUserStatus::NotFound,
        }
    }

    /// The user that was unlocked.
    async fn user(&self) -> Option<User> {
        match self {
            Self::Unlocked(user) => Some(User(user.clone())),
            Self::NotFound => None,
        }
    }
}

/// The input for the `setCanRequestAdmin` mutation.
#[derive(InputObject)]
struct SetCanRequestAdminInput {
    /// The ID of the user to update.
    user_id: ID,

    /// Whether the user can request admin.
    can_request_admin: bool,
}

/// The payload for the `setCanRequestAdmin` mutation.
#[derive(Description)]
enum SetCanRequestAdminPayload {
    /// The user was updated.
    Updated(mas_data_model::User),

    /// The user was not found.
    NotFound,
}

#[Object(use_type_description)]
impl SetCanRequestAdminPayload {
    /// The user that was updated.
    async fn user(&self) -> Option<User> {
        match self {
            Self::Updated(user) => Some(User(user.clone())),
            Self::NotFound => None,
        }
    }
}

/// The input for the `allowUserCrossSigningReset` mutation.
#[derive(InputObject)]
struct AllowUserCrossSigningResetInput {
    /// The ID of the user to update.
    user_id: ID,
}

/// The payload for the `allowUserCrossSigningReset` mutation.
#[derive(Description)]
enum AllowUserCrossSigningResetPayload {
    /// The user was updated.
    Allowed(mas_data_model::User),

    /// The user was not found.
    NotFound,
}

#[Object(use_type_description)]
impl AllowUserCrossSigningResetPayload {
    /// The user that was updated.
    async fn user(&self) -> Option<User> {
        match self {
            Self::Allowed(user) => Some(User(user.clone())),
            Self::NotFound => None,
        }
    }
}

/// The input for the `setPassword` mutation.
#[derive(InputObject)]
struct SetPasswordInput {
    /// The ID of the user to set the password for.
    /// If you are not a server administrator then this must be your own user
    /// ID.
    user_id: ID,

    /// The current password of the user.
    /// Required if you are not a server administrator.
    current_password: Option<String>,

    /// The new password for the user.
    new_password: String,
}

/// The input for the `setPasswordByRecovery` mutation.
#[derive(InputObject)]
struct SetPasswordByRecoveryInput {
    /// The recovery ticket to use.
    /// This identifies the user as well as proving authorisation to perform the
    /// recovery operation.
    ticket: String,

    /// The new password for the user.
    new_password: String,
}

/// The return type for the `setPassword` mutation.
#[derive(Description)]
struct SetPasswordPayload {
    status: SetPasswordStatus,
}

/// The status of the `setPassword` mutation.
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
enum SetPasswordStatus {
    /// The password was updated.
    Allowed,

    /// The user was not found.
    NotFound,

    /// The user doesn't have a current password to attempt to match against.
    NoCurrentPassword,

    /// The supplied current password was wrong.
    WrongPassword,

    /// The new password is invalid. For example, it may not meet configured
    /// security requirements.
    InvalidNewPassword,

    /// You aren't allowed to set the password for that user.
    /// This happens if you aren't setting your own password and you aren't a
    /// server administrator.
    NotAllowed,

    /// Password support has been disabled.
    /// This usually means that login is handled by an upstream identity
    /// provider.
    PasswordChangesDisabled,

    /// The specified recovery ticket does not exist.
    NoSuchRecoveryTicket,

    /// The specified recovery ticket has already been used and cannot be used
    /// again.
    RecoveryTicketAlreadyUsed,

    /// The specified recovery ticket has expired.
    ExpiredRecoveryTicket,

    /// Your account is locked and you can't change its password.
    AccountLocked,
}

#[Object(use_type_description)]
impl SetPasswordPayload {
    /// Status of the operation
    async fn status(&self) -> SetPasswordStatus {
        self.status
    }
}

/// The input for the `resendRecoveryEmail` mutation.
#[derive(InputObject)]
pub struct ResendRecoveryEmailInput {
    /// The recovery ticket to use.
    ticket: String,
}

/// The return type for the `resendRecoveryEmail` mutation.
#[derive(Description)]
pub enum ResendRecoveryEmailPayload {
    NoSuchRecoveryTicket,
    RateLimited,
    Sent { recovery_session_id: Ulid },
}

/// The status of the `resendRecoveryEmail` mutation.
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
pub enum ResendRecoveryEmailStatus {
    /// The recovery ticket was not found.
    NoSuchRecoveryTicket,

    /// The rate limit was exceeded.
    RateLimited,

    /// The recovery email was sent.
    Sent,
}

#[Object(use_type_description)]
impl ResendRecoveryEmailPayload {
    /// Status of the operation
    async fn status(&self) -> ResendRecoveryEmailStatus {
        match self {
            Self::NoSuchRecoveryTicket => ResendRecoveryEmailStatus::NoSuchRecoveryTicket,
            Self::RateLimited => ResendRecoveryEmailStatus::RateLimited,
            Self::Sent { .. } => ResendRecoveryEmailStatus::Sent,
        }
    }

    /// URL to continue the recovery process
    async fn progress_url(&self, context: &Context<'_>) -> Option<Url> {
        let state = context.state();
        let url_builder = state.url_builder();
        match self {
            Self::NoSuchRecoveryTicket | Self::RateLimited => None,
            Self::Sent {
                recovery_session_id,
            } => {
                let route = mas_router::AccountRecoveryProgress::new(*recovery_session_id);
                Some(url_builder.absolute_url_for(&route))
            }
        }
    }
}

/// The input for the `deactivateUser` mutation.
#[derive(InputObject)]
pub struct DeactivateUserInput {
    /// Whether to ask the homeserver to GDPR-erase the user
    ///
    /// This is equivalent to the `erase` parameter on the
    /// `/_matrix/client/v3/account/deactivate` C-S API, which is
    /// implementation-specific.
    ///
    /// What Synapse does is documented here:
    /// <https://element-hq.github.io/synapse/latest/admin_api/user_admin_api.html#deactivate-account>
    hs_erase: bool,

    /// The password of the user to deactivate.
    password: Option<String>,
}

/// The payload for the `deactivateUser` mutation.
#[derive(Description)]
pub enum DeactivateUserPayload {
    /// The user was deactivated.
    Deactivated(mas_data_model::User),

    /// The password was wrong or missing.
    IncorrectPassword,
}

/// The status of the `deactivateUser` mutation.
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
pub enum DeactivateUserStatus {
    /// The user was deactivated.
    Deactivated,

    /// The password was wrong.
    IncorrectPassword,
}

#[Object(use_type_description)]
impl DeactivateUserPayload {
    /// Status of the operation
    async fn status(&self) -> DeactivateUserStatus {
        match self {
            Self::Deactivated(_) => DeactivateUserStatus::Deactivated,
            Self::IncorrectPassword => DeactivateUserStatus::IncorrectPassword,
        }
    }

    async fn user(&self) -> Option<User> {
        match self {
            Self::Deactivated(user) => Some(User(user.clone())),
            Self::IncorrectPassword => None,
        }
    }
}

/// The input for the `registerUserInitiate` mutation.
#[derive(InputObject)]
struct RegisterUserInitiateInput {
    /// Desired username (localpart).
    username: String,

    /// Account password.
    password: String,

    /// Password confirmation. Must match `password`.
    password_confirm: Option<String>,

    /// Optional email address. Required if server config says so.
    email: Option<String>,

    /// Optional registration token. Required if server config says so.
    registration_token: Option<String>,

    /// Whether the user accepts the terms of service. Required if the server has a ToS.
    accept_terms: Option<bool>,

    /// The language to use for emails.
    #[graphql(default = "en")]
    language: String,

    /// CAPTCHA response. Required if the server has CAPTCHA configured.
    captcha_response: Option<String>,
}

/// The status of the `registerUserInitiate` mutation.
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
pub enum RegisterUserInitiateStatus {
    /// Registration is complete; user and session were created.
    Complete,

    /// Additional steps are required before registration finishes.
    Pending,

    /// Input validation failed.
    Failed,
}

/// The payload for the `registerUserInitiate` mutation.
#[derive(Description)]
pub enum RegisterUserInitiatePayload {
    Complete(mas_data_model::User, mas_data_model::BrowserSession),
    Pending {
        session_id: ID,
        next_steps: Vec<RegistrationStep>,
    },
    Failed(Vec<RegistrationFieldError>),
}

/// A step the client must complete to finish registration.
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
pub enum RegistrationStepType {
    EmailVerification,
}

/// A step descriptor.
#[derive(SimpleObject, Clone)]
pub struct RegistrationStep {
    step_type: RegistrationStepType,
}

/// A field-level validation error.
#[derive(SimpleObject, Clone)]
pub struct RegistrationFieldError {
    field: String,
    message: String,
}

#[Object(use_type_description)]
impl RegisterUserInitiatePayload {
    async fn status(&self) -> RegisterUserInitiateStatus {
        match self {
            Self::Complete(_, _) => RegisterUserInitiateStatus::Complete,
            Self::Pending { .. } => RegisterUserInitiateStatus::Pending,
            Self::Failed(_) => RegisterUserInitiateStatus::Failed,
        }
    }

    async fn user(&self) -> Option<User> {
        match self {
            Self::Complete(user, _) => Some(User(user.clone())),
            _ => None,
        }
    }

    async fn browser_session(&self) -> Option<crate::graphql::model::BrowserSession> {
        match self {
            Self::Complete(_, session) => {
                Some(crate::graphql::model::BrowserSession(session.clone()))
            }
            _ => None,
        }
    }

    async fn session_id(&self) -> Option<ID> {
        match self {
            Self::Pending { session_id, .. } => Some(session_id.clone()),
            _ => None,
        }
    }

    async fn next_steps(&self) -> Option<Vec<RegistrationStep>> {
        match self {
            Self::Pending { next_steps, .. } => Some(next_steps.clone()),
            _ => None,
        }
    }

    async fn errors(&self) -> Option<Vec<RegistrationFieldError>> {
        match self {
            Self::Failed(errors) => Some(errors.clone()),
            _ => None,
        }
    }
}

#[derive(InputObject)]
struct CompleteRegistrationStepInput {
    session_id: ID,
    step_type: RegistrationStepType,
    /// Step-specific data. For EmailVerification: JSON {"code": "123456"}
    data: Option<Json<serde_json::Value>>,
}

#[derive(Enum, Copy, Clone, Eq, PartialEq)]
pub enum CompleteRegistrationStepStatus {
    Complete,
    Pending,
    Failed,
}

/// The payload for the `completeRegistrationStep` mutation.
#[derive(Description)]
pub enum CompleteRegistrationStepPayload {
    Complete(mas_data_model::User, mas_data_model::BrowserSession),
    Pending {
        next_steps: Vec<RegistrationStep>,
    },
    Failed(Vec<RegistrationFieldError>),
}

#[Object(use_type_description)]
impl CompleteRegistrationStepPayload {
    async fn status(&self) -> CompleteRegistrationStepStatus {
        match self {
            Self::Complete(_, _) => CompleteRegistrationStepStatus::Complete,
            Self::Pending { .. } => CompleteRegistrationStepStatus::Pending,
            Self::Failed(_) => CompleteRegistrationStepStatus::Failed,
        }
    }

    async fn user(&self) -> Option<User> {
        match self {
            Self::Complete(u, _) => Some(User(u.clone())),
            _ => None,
        }
    }

    async fn browser_session(&self) -> Option<crate::graphql::model::BrowserSession> {
        match self {
            Self::Complete(_, s) => Some(crate::graphql::model::BrowserSession(s.clone())),
            _ => None,
        }
    }

    async fn next_steps(&self) -> Option<Vec<RegistrationStep>> {
        match self {
            Self::Pending { next_steps } => Some(next_steps.clone()),
            _ => None,
        }
    }

    async fn errors(&self) -> Option<Vec<RegistrationFieldError>> {
        match self {
            Self::Failed(e) => Some(e.clone()),
            _ => None,
        }
    }
}

#[derive(InputObject)]
struct ResendRegistrationEmailInput {
    session_id: ID,
}

#[derive(Enum, Copy, Clone, Eq, PartialEq)]
pub enum ResendRegistrationEmailStatus {
    Sent,
    Failed,
}

#[derive(SimpleObject)]
struct ResendRegistrationEmailPayload {
    status: ResendRegistrationEmailStatus,
    errors: Option<Vec<RegistrationFieldError>>,
}

fn valid_username_character(c: char) -> bool {
    c.is_ascii_lowercase()
        || c.is_ascii_digit()
        || c == '='
        || c == '_'
        || c == '-'
        || c == '.'
        || c == '/'
        || c == '+'
}

// XXX: this should probably be moved somewhere else
fn username_valid(username: &str) -> bool {
    if username.is_empty() || username.len() > 255 {
        return false;
    }

    // Should not start with an underscore
    if username.starts_with('_') {
        return false;
    }

    // Should only contain valid characters
    if !username.chars().all(valid_username_character) {
        return false;
    }

    true
}

#[Object]
impl UserMutations {
    /// Add a user. This is only available to administrators.
    async fn add_user(
        &self,
        ctx: &Context<'_>,
        input: AddUserInput,
    ) -> Result<AddUserPayload, async_graphql::Error> {
        let state = ctx.state();
        let requester = ctx.requester();
        let clock = state.clock();
        let mut rng = state.rng();

        if !requester.is_admin() {
            return Err(async_graphql::Error::new("Unauthorized"));
        }

        let mut repo = state.repository().await?;

        if let Some(user) = repo.user().find_by_username(&input.username).await? {
            return Ok(AddUserPayload::Exists(user));
        }

        // Do some basic check on the username
        if !username_valid(&input.username) {
            return Ok(AddUserPayload::Invalid);
        }

        // Ask the homeserver if the username is available
        let homeserver_available = state
            .homeserver_connection()
            .is_localpart_available(&input.username)
            .await?;

        if !homeserver_available {
            if !input.skip_homeserver_check.unwrap_or(false) {
                return Ok(AddUserPayload::Reserved);
            }

            // If we skipped the check, we still want to shout about it
            warn!("Skipped homeserver check for username {}", input.username);
        }

        let user = repo.user().add(&mut rng, &clock, input.username).await?;

        repo.queue_job()
            .schedule_job(&mut rng, &clock, ProvisionUserJob::new(&user))
            .await?;

        repo.save().await?;

        Ok(AddUserPayload::Added(user))
    }

    /// Lock a user. This is only available to administrators.
    async fn lock_user(
        &self,
        ctx: &Context<'_>,
        input: LockUserInput,
    ) -> Result<LockUserPayload, async_graphql::Error> {
        let state = ctx.state();
        let clock = state.clock();
        let mut rng = state.rng();
        let requester = ctx.requester();

        if !requester.is_admin() {
            return Err(async_graphql::Error::new("Unauthorized"));
        }

        let mut repo = state.repository().await?;

        let user_id = NodeType::User.extract_ulid(&input.user_id)?;
        let user = repo.user().lookup(user_id).await?;

        let Some(user) = user else {
            return Ok(LockUserPayload::NotFound);
        };

        let deactivate = input.deactivate.unwrap_or(false);

        let user = repo.user().lock(&state.clock(), user).await?;

        // Schedule a job to provision the user so that the lock flag is propagated
        // to Synapse
        repo.queue_job()
            .schedule_job(&mut rng, &clock, ProvisionUserJob::new(&user))
            .await?;

        if deactivate {
            info!(%user.id, "Scheduling deactivation of user");
            repo.queue_job()
                .schedule_job(&mut rng, &clock, DeactivateUserJob::new(&user, deactivate))
                .await?;
        }

        repo.save().await?;

        Ok(LockUserPayload::Locked(user))
    }

    /// Unlock and reactivate a user. This is only available to administrators.
    async fn unlock_user(
        &self,
        ctx: &Context<'_>,
        input: UnlockUserInput,
    ) -> Result<UnlockUserPayload, async_graphql::Error> {
        let state = ctx.state();
        let clock = state.clock();
        let mut rng = state.rng();
        let requester = ctx.requester();
        let matrix = state.homeserver_connection();

        if !requester.is_admin() {
            return Err(async_graphql::Error::new("Unauthorized"));
        }

        let mut repo = state.repository().await?;
        let user_id = NodeType::User.extract_ulid(&input.user_id)?;
        let user = repo.user().lookup(user_id).await?;

        let Some(user) = user else {
            return Ok(UnlockUserPayload::NotFound);
        };

        // Call the homeserver synchronously to reactivate the user
        matrix.reactivate_user(&user.username).await?;

        // Now reactivate & unlock the user in our database
        let user = repo.user().reactivate(user).await?;
        let user = repo.user().unlock(user).await?;

        // Schedule a job to provision the user so that the lock flag is propagated
        // to Synapse
        repo.queue_job()
            .schedule_job(&mut rng, &clock, ProvisionUserJob::new(&user))
            .await?;

        repo.save().await?;

        Ok(UnlockUserPayload::Unlocked(user))
    }

    /// Set whether a user can request admin. This is only available to
    /// administrators.
    async fn set_can_request_admin(
        &self,
        ctx: &Context<'_>,
        input: SetCanRequestAdminInput,
    ) -> Result<SetCanRequestAdminPayload, async_graphql::Error> {
        let state = ctx.state();
        let requester = ctx.requester();

        if !requester.is_admin() {
            return Err(async_graphql::Error::new("Unauthorized"));
        }

        let mut repo = state.repository().await?;

        let user_id = NodeType::User.extract_ulid(&input.user_id)?;
        let user = repo.user().lookup(user_id).await?;

        let Some(user) = user else {
            return Ok(SetCanRequestAdminPayload::NotFound);
        };

        let user = repo
            .user()
            .set_can_request_admin(user, input.can_request_admin)
            .await?;

        repo.save().await?;

        Ok(SetCanRequestAdminPayload::Updated(user))
    }

    /// Temporarily allow user to reset their cross-signing keys.
    async fn allow_user_cross_signing_reset(
        &self,
        ctx: &Context<'_>,
        input: AllowUserCrossSigningResetInput,
    ) -> Result<AllowUserCrossSigningResetPayload, async_graphql::Error> {
        let state = ctx.state();
        let user_id = NodeType::User.extract_ulid(&input.user_id)?;
        let requester = ctx.requester();

        if !requester.is_owner_or_admin(&UserId(user_id)) {
            return Err(async_graphql::Error::new("Unauthorized"));
        }

        let mut repo = state.repository().await?;
        let user = repo.user().lookup(user_id).await?;
        repo.cancel().await?;

        let Some(user) = user else {
            return Ok(AllowUserCrossSigningResetPayload::NotFound);
        };

        let conn = state.homeserver_connection();
        conn.allow_cross_signing_reset(&user.username)
            .await
            .context("Failed to allow cross-signing reset")?;

        Ok(AllowUserCrossSigningResetPayload::Allowed(user))
    }

    /// Set the password for a user.
    ///
    /// This can be used by server administrators to set any user's password,
    /// or, provided the capability hasn't been disabled on this server,
    /// by a user to change their own password as long as they know their
    /// current password.
    async fn set_password(
        &self,
        ctx: &Context<'_>,
        input: SetPasswordInput,
    ) -> Result<SetPasswordPayload, async_graphql::Error> {
        let state = ctx.state();
        let user_id = NodeType::User.extract_ulid(&input.user_id)?;
        let requester = ctx.requester();

        if !requester.is_owner_or_admin(&UserId(user_id)) {
            return Err(async_graphql::Error::new("Unauthorized"));
        }

        if input.new_password.is_empty() {
            // TODO Expose the reason for the policy violation
            // This involves redesigning the error handling
            // Idea would be to expose an errors array in the response,
            // with a list of union of different error kinds.
            return Ok(SetPasswordPayload {
                status: SetPasswordStatus::InvalidNewPassword,
            });
        }

        let password_manager = state.password_manager();

        if !password_manager.is_enabled() {
            return Ok(SetPasswordPayload {
                status: SetPasswordStatus::PasswordChangesDisabled,
            });
        }

        if !password_manager.is_password_complex_enough(&input.new_password)? {
            return Ok(SetPasswordPayload {
                status: SetPasswordStatus::InvalidNewPassword,
            });
        }

        let mut repo = state.repository().await?;
        let Some(user) = repo.user().lookup(user_id).await? else {
            return Ok(SetPasswordPayload {
                status: SetPasswordStatus::NotFound,
            });
        };

        if !requester.is_admin() {
            // If the user isn't an admin, we:
            // - check that password changes are enabled
            // - check that they know their current password

            if !state.site_config().password_change_allowed {
                return Ok(SetPasswordPayload {
                    status: SetPasswordStatus::PasswordChangesDisabled,
                });
            }

            let Some(active_password) = repo.user_password().active(&user).await? else {
                // The user has no current password, so can't verify against one.
                // In the future, it may be desirable to let the user set a password without any
                // other verification instead.

                return Ok(SetPasswordPayload {
                    status: SetPasswordStatus::NoCurrentPassword,
                });
            };

            let Some(current_password_attempt) = input.current_password else {
                return Err(async_graphql::Error::new(
                    "You must supply `currentPassword` to change your own password if you are not an administrator",
                ));
            };

            if !password_manager
                .verify(
                    active_password.version,
                    Zeroizing::new(current_password_attempt),
                    active_password.hashed_password,
                )
                .await?
                .is_success()
            {
                return Ok(SetPasswordPayload {
                    status: SetPasswordStatus::WrongPassword,
                });
            }
        }

        let (new_password_version, new_password_hash) = password_manager
            .hash(state.rng(), Zeroizing::new(input.new_password))
            .await?;

        repo.user_password()
            .add(
                &mut state.rng(),
                &state.clock(),
                &user,
                new_password_version,
                new_password_hash,
                None,
            )
            .await?;

        repo.save().await?;

        Ok(SetPasswordPayload {
            status: SetPasswordStatus::Allowed,
        })
    }

    /// Set the password for yourself, using a recovery ticket sent by e-mail.
    async fn set_password_by_recovery(
        &self,
        ctx: &Context<'_>,
        input: SetPasswordByRecoveryInput,
    ) -> Result<SetPasswordPayload, async_graphql::Error> {
        let state = ctx.state();
        let requester = ctx.requester();
        let clock = state.clock();
        if !requester.is_unauthenticated() {
            return Err(async_graphql::Error::new(
                "Account recovery is only for anonymous users.",
            ));
        }

        let password_manager = state.password_manager();

        if !password_manager.is_enabled() || !state.site_config().account_recovery_allowed {
            return Ok(SetPasswordPayload {
                status: SetPasswordStatus::PasswordChangesDisabled,
            });
        }

        if !password_manager.is_password_complex_enough(&input.new_password)? {
            return Ok(SetPasswordPayload {
                status: SetPasswordStatus::InvalidNewPassword,
            });
        }

        let mut repo = state.repository().await?;

        let Some(ticket) = repo.user_recovery().find_ticket(&input.ticket).await? else {
            return Ok(SetPasswordPayload {
                status: SetPasswordStatus::NoSuchRecoveryTicket,
            });
        };

        let session = repo
            .user_recovery()
            .lookup_session(ticket.user_recovery_session_id)
            .await?
            .context("Unknown session")?;

        if session.consumed_at.is_some() {
            return Ok(SetPasswordPayload {
                status: SetPasswordStatus::RecoveryTicketAlreadyUsed,
            });
        }

        if !ticket.active(clock.now()) {
            return Ok(SetPasswordPayload {
                status: SetPasswordStatus::ExpiredRecoveryTicket,
            });
        }

        let user_email = repo
            .user_email()
            .lookup(ticket.user_email_id)
            .await?
            .context("Unknown email address")?;

        let user = repo
            .user()
            .lookup(user_email.user_id)
            .await?
            .context("Invalid user")?;

        if !user.is_valid() {
            return Ok(SetPasswordPayload {
                status: SetPasswordStatus::AccountLocked,
            });
        }

        let (new_password_version, new_password_hash) = password_manager
            .hash(state.rng(), Zeroizing::new(input.new_password))
            .await?;

        repo.user_password()
            .add(
                &mut state.rng(),
                &state.clock(),
                &user,
                new_password_version,
                new_password_hash,
                None,
            )
            .await?;

        // Mark the session as consumed
        repo.user_recovery()
            .consume_ticket(&clock, ticket, session)
            .await?;

        repo.save().await?;

        Ok(SetPasswordPayload {
            status: SetPasswordStatus::Allowed,
        })
    }

    /// Resend a user recovery email
    ///
    /// This is used when a user opens a recovery link that has expired. In this
    /// case, we display a link for them to get a new recovery email, which
    /// calls this mutation.
    pub async fn resend_recovery_email(
        &self,
        ctx: &Context<'_>,
        input: ResendRecoveryEmailInput,
    ) -> Result<ResendRecoveryEmailPayload, async_graphql::Error> {
        let state = ctx.state();
        let requester = ctx.requester();
        let clock = state.clock();
        let mut rng = state.rng();
        let limiter = state.limiter();
        let mut repo = state.repository().await?;

        let Some(recovery_ticket) = repo.user_recovery().find_ticket(&input.ticket).await? else {
            return Ok(ResendRecoveryEmailPayload::NoSuchRecoveryTicket);
        };

        let recovery_session = repo
            .user_recovery()
            .lookup_session(recovery_ticket.user_recovery_session_id)
            .await?
            .context("Could not load recovery session")?;

        if let Err(e) =
            limiter.check_account_recovery(requester.fingerprint(), &recovery_session.email)
        {
            tracing::warn!(error = &e as &dyn std::error::Error);
            return Ok(ResendRecoveryEmailPayload::RateLimited);
        }

        // Schedule a new batch of emails
        repo.queue_job()
            .schedule_job(
                &mut rng,
                &clock,
                SendAccountRecoveryEmailsJob::new(&recovery_session),
            )
            .await?;

        repo.save().await?;

        Ok(ResendRecoveryEmailPayload::Sent {
            recovery_session_id: recovery_session.id,
        })
    }

    /// Deactivate the current user account
    ///
    /// If the user has a password, it *must* be supplied in the `password`
    /// field.
    async fn deactivate_user(
        &self,
        ctx: &Context<'_>,
        input: DeactivateUserInput,
    ) -> Result<DeactivateUserPayload, async_graphql::Error> {
        let state = ctx.state();
        let mut rng = state.rng();
        let clock = state.clock();
        let requester = ctx.requester();
        let site_config = state.site_config();

        // Only allow calling this if the requester is a browser session
        let Some(browser_session) = requester.browser_session() else {
            return Err(async_graphql::Error::new("Unauthorized"));
        };

        if !site_config.account_deactivation_allowed {
            return Err(async_graphql::Error::new(
                "Account deactivation is not allowed on this server",
            ));
        }

        let mut repo = state.repository().await?;
        if !verify_password_if_needed(
            requester,
            site_config,
            &state.password_manager(),
            input.password,
            &browser_session.user,
            &mut repo,
        )
        .await?
        {
            return Ok(DeactivateUserPayload::IncorrectPassword);
        }

        // Deactivate the user right away
        let user = repo
            .user()
            .deactivate(&state.clock(), browser_session.user.clone())
            .await?;

        // and then schedule a job to deactivate it fully
        repo.queue_job()
            .schedule_job(
                &mut rng,
                &clock,
                DeactivateUserJob::new(&user, input.hs_erase),
            )
            .await?;

        repo.save().await?;

        Ok(DeactivateUserPayload::Deactivated(user))
    }

    /// Initiate a user registration.
    async fn register_user_initiate(
        &self,
        ctx: &Context<'_>,
        input: RegisterUserInitiateInput,
    ) -> Result<RegisterUserInitiatePayload, async_graphql::Error> {
        let state = ctx.state();
        let clock = state.clock();
        let mut rng = state.rng();
        let site_config = state.site_config().clone();
        let password_manager = state.password_manager();
        let homeserver = state.homeserver_connection();
        let limiter = state.limiter();
        let requester = ctx.requester();

        // Only allow public (non-authenticated) requesters
        if !requester.is_unauthenticated() {
            return Err(async_graphql::Error::new("Already authenticated"));
        }

        if !site_config.password_registration_enabled {
            return Err(async_graphql::Error::new(
                "Password registration is disabled",
            ));
        }

        let mut repo = state.repository().await?;
        let mut errors: Vec<RegistrationFieldError> = Vec::new();

        // Validate username
        if input.username.is_empty() {
            errors.push(RegistrationFieldError {
                field: "username".to_owned(),
                message: "Username is required".to_owned(),
            });
        } else if repo.user().exists(&input.username).await? {
            errors.push(RegistrationFieldError {
                field: "username".to_owned(),
                message: "Username is already taken".to_owned(),
            });
        } else if !homeserver
            .is_localpart_available(&input.username)
            .await
            .map_err(|e| async_graphql::Error::new(e.to_string()))?
        {
            errors.push(RegistrationFieldError {
                field: "username".to_owned(),
                message: "Username is not available".to_owned(),
            });
        }

        // Validate password
        if input.password.is_empty() {
            errors.push(RegistrationFieldError {
                field: "password".to_owned(),
                message: "Password is required".to_owned(),
            });
        } else if !password_manager.is_password_complex_enough(&input.password)? {
            errors.push(RegistrationFieldError {
                field: "password".to_owned(),
                message: "Password is too weak".to_owned(),
            });
        }

        // Validate password confirmation
        if let Some(ref confirm) = input.password_confirm {
            if *confirm != input.password {
                errors.push(RegistrationFieldError {
                    field: "password_confirm".to_owned(),
                    message: "Passwords do not match".to_owned(),
                });
            }
        }

        // Validate email if required
        let email = if site_config.password_registration_email_required {
            match input.email {
                Some(ref e) if !e.is_empty() => {
                    if e.parse::<lettre::Address>().is_err() {
                        errors.push(RegistrationFieldError {
                            field: "email".to_owned(),
                            message: "Email address is invalid".to_owned(),
                        });
                    }
                    Some(e.clone())
                }
                _ => {
                    errors.push(RegistrationFieldError {
                        field: "email".to_owned(),
                        message: "Email is required".to_owned(),
                    });
                    None
                }
            }
        } else {
            match input.email.filter(|e| !e.is_empty()) {
                Some(ref e) if e.parse::<lettre::Address>().is_err() => {
                    errors.push(RegistrationFieldError {
                        field: "email".to_owned(),
                        message: "Email address is invalid".to_owned(),
                    });
                    Some(e.clone())
                }
                e => e,
            }
        };

        // Validate registration token if required
        let registration_token_id = if site_config.registration_token_required {
            match input.registration_token {
                Some(token) if !token.is_empty() => {
                    let token_record = repo
                        .user_registration_token()
                        .find_by_token(&token)
                        .await?;
                    match token_record {
                        Some(t) if t.is_valid(clock.now()) => Some(t.id),
                        _ => {
                            errors.push(RegistrationFieldError {
                                field: "registration_token".to_owned(),
                                message: "Invalid or expired registration token".to_owned(),
                            });
                            None
                        }
                    }
                }
                _ => {
                    errors.push(RegistrationFieldError {
                        field: "registration_token".to_owned(),
                        message: "Registration token is required".to_owned(),
                    });
                    None
                }
            }
        } else {
            None
        };

        // Validate terms acceptance if ToS is configured
        if site_config.tos_uri.is_some() && input.accept_terms != Some(true) {
            errors.push(RegistrationFieldError {
                field: "accept_terms".to_owned(),
                message: "You must accept the terms of service".to_owned(),
            });
        }

        // Validate CAPTCHA if configured
        if site_config.captcha.is_some() {
            let captcha_form = crate::captcha::Form::from_response(input.captcha_response.clone());
            if let Err(e) = captcha_form
                .verify(
                    requester.ip_address,
                    state.http_client(),
                    state.url_builder().public_hostname(),
                    site_config.captcha.as_ref(),
                )
                .await
            {
                tracing::warn!(error = &e as &dyn std::error::Error, "CAPTCHA verification failed");
                errors.push(RegistrationFieldError {
                    field: "captcha".to_owned(),
                    message: "CAPTCHA verification failed".to_owned(),
                });
            }
        }

        // Rate limiting
        if errors.is_empty() {
            if let Err(e) = limiter.check_registration(requester.fingerprint()) {
                tracing::warn!(error = &e as &dyn std::error::Error);
                errors.push(RegistrationFieldError {
                    field: "form".to_owned(),
                    message: "Too many registration attempts".to_owned(),
                });
            }

            if let Some(ref email) = email {
                if let Err(e) = limiter.check_email_authentication_email(requester.fingerprint(), email) {
                    tracing::warn!(error = &e as &dyn std::error::Error);
                    errors.push(RegistrationFieldError {
                        field: "email".to_owned(),
                        message: "Too many email authentication attempts".to_owned(),
                    });
                }
            }
        }

        // Policy evaluation
        if errors.is_empty() {
            let mut policy = state.policy().await?;
            let res = policy
                .evaluate_register(mas_policy::RegisterInput {
                    registration_method: mas_policy::RegistrationMethod::Password,
                    username: &input.username,
                    email: email.as_deref(),
                    requester: requester.for_policy(),
                })
                .await?;

            for violation in res.violations {
                match violation.field.as_deref() {
                    Some("email") => errors.push(RegistrationFieldError {
                        field: "email".to_owned(),
                        message: violation.msg,
                    }),
                    Some("username") => errors.push(RegistrationFieldError {
                        field: "username".to_owned(),
                        message: violation.msg,
                    }),
                    Some("password") => errors.push(RegistrationFieldError {
                        field: "password".to_owned(),
                        message: violation.msg,
                    }),
                    _ => errors.push(RegistrationFieldError {
                        field: "form".to_owned(),
                        message: violation.msg,
                    }),
                }
            }
        }

        if !errors.is_empty() {
            return Ok(RegisterUserInitiatePayload::Failed(errors));
        }

        // All valid: create registration session
        let ip_address = requester.ip_address;
        let user_agent = requester.user_agent.clone();
        let post_auth_action: Option<mas_router::PostAuthAction> = None;
        let post_auth_action_value = post_auth_action.map(serde_json::to_value).transpose()?;

        let registration = repo
            .user_registration()
            .add(&mut *rng, &*clock, input.username.clone(), ip_address, user_agent, post_auth_action_value)
            .await?;

        // Set terms URL if present
        let registration = if let Some(tos_uri) = &site_config.tos_uri {
            repo.user_registration()
                .set_terms_url(registration, tos_uri.clone())
                .await?
        } else {
            registration
        };

        // Attach email if provided
        let registration = if let Some(email) = email {
            let user_email_auth = repo
                .user_email()
                .add_authentication_for_registration(&mut *rng, &*clock, email, &registration)
                .await?;
            repo.queue_job()
                .schedule_job(
                    &mut *rng,
                    &*clock,
                    SendEmailAuthenticationCodeJob::new(
                        &user_email_auth,
                        input.language,
                    ),
                )
                .await?;
            repo.user_registration()
                .set_email_authentication(registration, &user_email_auth)
                .await?
        } else {
            registration
        };

        // Hash and store password
        let password = Zeroizing::new(input.password);
        let (version, hashed_password) = password_manager
            .hash(rng, password)
            .await
            .map_err(|e| async_graphql::Error::new(e.to_string()))?;
        let registration = repo
            .user_registration()
            .set_password(registration, hashed_password, version)
            .await?;

        // Link registration token if used
        let registration = if let Some(token_id) = registration_token_id {
            let token = repo
                .user_registration_token()
                .lookup(token_id)
                .await?
                .context("Token not found")
                .map_err(|e: anyhow::Error| async_graphql::Error::new(e.to_string()))?;
            repo.user_registration()
                .set_registration_token(registration, &token)
                .await?
        } else {
            registration
        };

        // Determine next steps
        let mut next_steps: Vec<RegistrationStep> = Vec::new();
        if registration.email_authentication_id.is_some() {
            next_steps.push(RegistrationStep {
                step_type: RegistrationStepType::EmailVerification,
            });
        }

        // If no pending steps, finish immediately
        if next_steps.is_empty() {
            let (user, session) = Self::complete_registration(
                &mut repo,
                &*clock,
                state.rng(),
                registration,
                homeserver,
            )
            .await?;
            repo.save().await?;
            return Ok(RegisterUserInitiatePayload::Complete(user, session));
        }

        repo.save().await?;
        Ok(RegisterUserInitiatePayload::Pending {
            session_id: registration.id.to_string().into(),
            next_steps,
        })
    }

    async fn complete_registration_step(
        &self,
        ctx: &Context<'_>,
        input: CompleteRegistrationStepInput,
    ) -> Result<CompleteRegistrationStepPayload, async_graphql::Error> {
        let state = ctx.state();
        let clock = state.clock();
        let rng = state.rng();
        let homeserver = state.homeserver_connection();
        let limiter = state.limiter();
        let mut repo = state.repository().await?;

        let session_id: Ulid = input
            .session_id
            .parse()
            .map_err(|_| async_graphql::Error::new("Invalid session ID"))?;

        let registration = repo
            .user_registration()
            .lookup(session_id)
            .await?
            .context("Registration session not found")
            .map_err(|e: anyhow::Error| async_graphql::Error::new(e.to_string()))?;

        if registration.completed_at.is_some() {
            return Err(async_graphql::Error::new("Registration already completed"));
        }

        // Expiration check (1 hour hardcoded to match web handler)
        if clock.now() - registration.created_at > chrono::Duration::hours(1) {
            return Err(async_graphql::Error::new(
                "Registration session has expired",
            ));
        }

        let mut errors = Vec::new();

        match input.step_type {
            RegistrationStepType::EmailVerification => {
                let code = input
                    .data
                    .as_ref()
                    .and_then(|d| d.0.get("code").and_then(|v| v.as_str()))
                    .unwrap_or("");

                if let Some(email_auth_id) = registration.email_authentication_id {
                    let email_auth = repo
                        .user_email()
                        .lookup_authentication(email_auth_id)
                        .await?
                        .context("Email authentication not found")
                        .map_err(|e: anyhow::Error| async_graphql::Error::new(e.to_string()))?;

                    // Rate limit attempts
                    if let Err(e) = limiter.check_email_authentication_attempt(&email_auth) {
                        tracing::warn!(error = &e as &dyn std::error::Error);
                        errors.push(RegistrationFieldError {
                            field: "code".to_owned(),
                            message: "Too many verification attempts".to_owned(),
                        });
                    } else if email_auth.completed_at.is_some() {
                        // Already verified
                    } else if code.is_empty() {
                        errors.push(RegistrationFieldError {
                            field: "code".to_owned(),
                            message: "Verification code is required".to_owned(),
                        });
                    } else {
                        let code_record = repo
                            .user_email()
                            .find_authentication_code(&email_auth, code)
                            .await?;
                        match code_record {
                            Some(c) if c.expires_at > clock.now() => {
                                let _completed = repo
                                    .user_email()
                                    .complete_authentication_with_code(&*clock, email_auth, &c)
                                    .await?;
                            }
                            _ => {
                                errors.push(RegistrationFieldError {
                                    field: "code".to_owned(),
                                    message: "Invalid or expired verification code".to_owned(),
                                });
                            }
                        }
                    }
                }
            }
        }

        if !errors.is_empty() {
            return Ok(CompleteRegistrationStepPayload::Failed(errors));
        }

        // Re-evaluate pending steps
        let refreshed = repo
            .user_registration()
            .lookup(session_id)
            .await?
            .context("Registration session not found")
            .map_err(|e: anyhow::Error| async_graphql::Error::new(e.to_string()))?;

        let mut next_steps = Vec::new();
        if let Some(email_auth_id) = refreshed.email_authentication_id {
            let email_auth = repo
                .user_email()
                .lookup_authentication(email_auth_id)
                .await?
                .context("Email auth missing")
                .map_err(|e: anyhow::Error| async_graphql::Error::new(e.to_string()))?;
            if email_auth.completed_at.is_none() {
                next_steps.push(RegistrationStep {
                    step_type: RegistrationStepType::EmailVerification,
                });
            }
        }

        if next_steps.is_empty() {
            let (user, session) = Self::complete_registration(
                &mut repo,
                &*clock,
                rng,
                refreshed,
                homeserver,
            )
            .await?;
            repo.save().await?;
            return Ok(CompleteRegistrationStepPayload::Complete(user, session));
        }

        repo.save().await?;
        Ok(CompleteRegistrationStepPayload::Pending { next_steps })
    }

    async fn resend_registration_email(
        &self,
        ctx: &Context<'_>,
        input: ResendRegistrationEmailInput,
    ) -> Result<ResendRegistrationEmailPayload, async_graphql::Error> {
        let state = ctx.state();
        let clock = state.clock();
        let mut rng = state.rng();
        let limiter = state.limiter();
        let requester = ctx.requester();
        let mut repo = state.repository().await?;

        let session_id: Ulid = input
            .session_id
            .parse()
            .map_err(|_| async_graphql::Error::new("Invalid session ID"))?;

        let registration = repo
            .user_registration()
            .lookup(session_id)
            .await?
            .context("Registration session not found")
            .map_err(|e: anyhow::Error| async_graphql::Error::new(e.to_string()))?;

        if let Some(email_auth_id) = registration.email_authentication_id {
            let email_auth = repo
                .user_email()
                .lookup_authentication(email_auth_id)
                .await?
                .context("Email authentication not found")
                .map_err(|e: anyhow::Error| async_graphql::Error::new(e.to_string()))?;

            if let Err(e) = limiter.check_email_authentication_send_code(requester.fingerprint(), &email_auth) {
                tracing::warn!(error = &e as &dyn std::error::Error);
                return Ok(ResendRegistrationEmailPayload {
                    status: ResendRegistrationEmailStatus::Failed,
                    errors: Some(vec![RegistrationFieldError {
                        field: "session".to_owned(),
                        message: "Rate limited. Please try again later.".to_owned(),
                    }]),
                });
            }

            repo.queue_job()
                .schedule_job(
                    &mut *rng,
                    &*clock,
                    SendEmailAuthenticationCodeJob::new(&email_auth, "en".to_owned()),
                )
                .await?;
            repo.save().await?;
            Ok(ResendRegistrationEmailPayload {
                status: ResendRegistrationEmailStatus::Sent,
                errors: None,
            })
        } else {
            Ok(ResendRegistrationEmailPayload {
                status: ResendRegistrationEmailStatus::Failed,
                errors: Some(vec![RegistrationFieldError {
                    field: "session".to_owned(),
                    message: "Email verification is not pending for this session.".to_owned(),
                }]),
            })
        }
    }
}

impl UserMutations {
    async fn complete_registration(
        repo: &mut mas_storage::BoxRepository,
        clock: &dyn mas_data_model::Clock,
        mut rng: mas_data_model::BoxRng,
        registration: mas_data_model::UserRegistration,
        homeserver: &dyn mas_matrix::HomeserverConnection,
    ) -> Result<(mas_data_model::User, mas_data_model::BrowserSession), async_graphql::Error> {
        use mas_storage::queue::QueueJobRepositoryExt;
        use mas_storage::queue::ProvisionUserJob;
        use mas_storage::user::{
            BrowserSessionRepository, UserEmailFilter, UserPasswordRepository,
            UserRegistrationTokenRepository, UserTermsRepository,
        };

        // Final availability checks
        if repo.user().exists(&registration.username).await? {
            return Err(async_graphql::Error::new("Username is already taken"));
        }
        if !homeserver.is_localpart_available(&registration.username).await? {
            return Err(async_graphql::Error::new("Username is not available"));
        }

        // Check email isn't already in use before we create the user
        let email_to_add = if let Some(email_auth_id) = registration.email_authentication_id {
            let email_auth = repo
                .user_email()
                .lookup_authentication(email_auth_id)
                .await?
                .context("Email auth not found")
                .map_err(|e: anyhow::Error| async_graphql::Error::new(e.to_string()))?;
            if repo
                .user_email()
                .count(UserEmailFilter::new().for_email(&email_auth.email))
                .await?
                > 0
            {
                return Err(async_graphql::Error::new("Email address already in use"));
            }
            Some(email_auth.email)
        } else {
            None
        };

        // Mark registration completed
        let registration = repo.user_registration().complete(clock, registration).await?;

        // Use token if present
        if let Some(token_id) = registration.user_registration_token_id {
            let token = repo
                .user_registration_token()
                .lookup(token_id)
                .await?
                .context("Token not found")
                .map_err(|e: anyhow::Error| async_graphql::Error::new(e.to_string()))?;
            repo.user_registration_token()
                .use_token(clock, token)
                .await?;
        }

        // Create user
        let user = repo
            .user()
            .add(&mut *rng, clock, registration.username.clone())
            .await?;

        // Create browser session
        let user_agent = registration.user_agent.clone();
        let session = repo
            .browser_session()
            .add(&mut *rng, clock, &user, user_agent)
            .await?;

        // Store password and authenticate the session
        if let Some(password) = registration.password {
            let user_password = repo
                .user_password()
                .add(
                    &mut *rng,
                    clock,
                    &user,
                    password.version,
                    password.hashed_password,
                    None,
                )
                .await?;
            repo.browser_session()
                .authenticate_with_password(&mut *rng, clock, &session, &user_password)
                .await?;
        }

        // Add email if present
        if let Some(email) = email_to_add {
            repo.user_email()
                .add(&mut *rng, clock, &user, email)
                .await?;
        }

        // Persist terms acceptance
        if let Some(terms_url) = registration.terms_url {
            repo.user_terms()
                .accept_terms(&mut *rng, clock, &user, terms_url)
                .await?;
        }

        // Queue provisioning on homeserver
        let mut job = ProvisionUserJob::new(&user);
        if let Some(display_name) = registration.display_name {
            job = job.set_display_name(display_name);
        }
        repo.queue_job()
            .schedule_job(&mut *rng, clock, job)
            .await?;

        Ok((user, session))
    }
}
