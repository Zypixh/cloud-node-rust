pub use self::blacklists::AttributeType;
pub use self::detector::{XssDetector, XssResult};
pub use self::html5::{Html5Flags, Html5State, TokenType};

mod blacklists;
mod detector;
mod html5;

#[cfg(test)]
mod tests;
