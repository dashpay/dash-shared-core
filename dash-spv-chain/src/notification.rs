use std::os::raw::c_void;
use std::sync::Arc;

pub const IDENTITY_DID_UPDATE_NOTIFICATION: &str = "DSIdentitiesDidUpdateNotification";
pub const INVITATION_DID_UPDATE_NOTIFICATION: &str = "DSInvitationDidUpdateNotification";

pub const CHAIN_MANAGER_NOTIFICATION_CHAIN_KEY: &str = "DSChainManagerNotificationChainKey";


pub const IDENTITY_UPDATE_EVENT_KEY_UPDATE: &str = "DSIdentityUpdateEventKeyUpdate";

pub const IDENTITY_UPDATE_EVENT_REGISTRATION: &str = "DSIdentityUpdateEventRegistration";

pub const IDENTITY_UPDATE_EVENT_CREDIT_BALANCE: &str = "DSIdentityUpdateEventCreditBalance";


pub trait NotificationRef {
    fn notification_ref(&self) -> &NotificationController;
}

pub struct NotificationController {
    pub notify_main_thread: Arc<dyn Fn(/*notification_name*/&str, /*user_info*/ *mut c_void)>,
}

impl NotificationController {
    pub fn new<
        NotifyMainThread: Fn(&str, *mut c_void) + Send + Sync + 'static
    >(
        notify_main_thread: NotifyMainThread
    ) -> NotificationController {
        Self {
            notify_main_thread: Arc::new(notify_main_thread),
        }
    }
}

impl NotificationController {
    pub fn notify_main_thread(
        &self,
        notification_name: &str,
        user_info: *mut c_void,
    ) {
        (self.notify_main_thread)(notification_name, user_info);
    }

    pub fn identity_did_update(&self, user_info: *mut c_void) {
        self.notify_main_thread(IDENTITY_DID_UPDATE_NOTIFICATION, user_info);
    }
    pub fn invitation_did_update(&self, user_info: *mut c_void) {
        self.notify_main_thread(INVITATION_DID_UPDATE_NOTIFICATION, user_info);
    }
}