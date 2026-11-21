pub(in crate::platform) mod connected;
mod physical;
pub(crate) mod rtmsg;
pub(in crate::platform) mod segment;

pub(in crate::platform) use connected::tunnel_interface_by_ipv4;
pub(in crate::platform) use physical::physical_default_interface;
