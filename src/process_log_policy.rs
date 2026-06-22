use pingora_core::{Error, ErrorSource, ErrorType};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessLogEventKind {
    RequestOutcome,
    ComponentHealth,
    BackgroundTask,
    Listener,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessLogSeverity {
    Debug,
    Warn,
    Error,
}

pub fn is_request_outcome_error(error: &Error, status: Option<u16>) -> bool {
    if matches!(error.etype(), ErrorType::HTTPStatus(_)) {
        return true;
    }

    match error.esource() {
        ErrorSource::Upstream => upstream_error_is_request_outcome(error.etype()),
        ErrorSource::Downstream => downstream_error_is_request_outcome(error.etype()),
        ErrorSource::Unset => unset_error_is_request_outcome(error.etype(), status),
        ErrorSource::Internal => matches!(error.etype(), ErrorType::HTTPStatus(_)),
    }
}

pub fn access_log_error_label(error: &Error, status: Option<u16>) -> &'static str {
    match error.esource() {
        ErrorSource::Upstream => match error.etype() {
            ErrorType::ConnectTimedout => "proxy: upstream_connect_timeout",
            ErrorType::ReadTimedout => "proxy: upstream_read_timeout",
            ErrorType::WriteTimedout => "proxy: upstream_write_timeout",
            ErrorType::TLSHandshakeTimedout => "proxy: upstream_tls_timeout",
            ErrorType::ConnectRefused => "proxy: upstream_connect_refused",
            ErrorType::ConnectNoRoute => "proxy: upstream_no_route",
            ErrorType::ConnectProxyFailure => "proxy: upstream_proxy_connect_failure",
            ErrorType::ConnectError => "proxy: upstream_connect_error",
            ErrorType::TLSHandshakeFailure
            | ErrorType::InvalidCert
            | ErrorType::HandshakeError
            | ErrorType::TLSWantX509Lookup => "proxy: upstream_tls_error",
            ErrorType::ReadError => "proxy: upstream_read_error",
            ErrorType::WriteError => "proxy: upstream_write_error",
            ErrorType::ConnectionClosed => "proxy: upstream_closed",
            ErrorType::H1Error | ErrorType::H2Error | ErrorType::InvalidH2 => {
                "proxy: upstream_protocol_error"
            }
            ErrorType::HTTPStatus(code) => status_label(*code),
            _ => "proxy: upstream_error",
        },
        ErrorSource::Downstream => match error.etype() {
            ErrorType::ReadTimedout => "proxy: downstream_read_timeout",
            ErrorType::WriteTimedout => "proxy: downstream_write_timeout",
            ErrorType::ReadError => "proxy: downstream_read_error",
            ErrorType::WriteError => "proxy: downstream_write_error",
            ErrorType::ConnectionClosed => "proxy: downstream_closed",
            ErrorType::InvalidHTTPHeader => "proxy: downstream_invalid_header",
            ErrorType::H1Error | ErrorType::H2Error | ErrorType::InvalidH2 => {
                "proxy: downstream_protocol_error"
            }
            ErrorType::HTTPStatus(code) => status_label(*code),
            _ => "proxy: downstream_error",
        },
        ErrorSource::Internal => match error.etype() {
            ErrorType::HTTPStatus(code) => status_label(*code),
            _ => "proxy: internal_error",
        },
        ErrorSource::Unset => match error.etype() {
            ErrorType::HTTPStatus(code) => status_label(*code),
            ErrorType::InvalidHTTPHeader => "proxy: invalid_header",
            _ => status.map(status_label).unwrap_or("proxy: request_error"),
        },
    }
}

pub fn should_emit_process_log(
    event_kind: ProcessLogEventKind,
    severity: ProcessLogSeverity,
    error: Option<&Error>,
    status: Option<u16>,
) -> bool {
    match event_kind {
        ProcessLogEventKind::RequestOutcome => error
            .map(|error| !is_request_outcome_error(error, status))
            .unwrap_or(false),
        ProcessLogEventKind::ComponentHealth
        | ProcessLogEventKind::BackgroundTask
        | ProcessLogEventKind::Listener => !matches!(severity, ProcessLogSeverity::Debug),
    }
}

fn upstream_error_is_request_outcome(error_type: &ErrorType) -> bool {
    matches!(
        error_type,
        ErrorType::ConnectTimedout
            | ErrorType::ConnectRefused
            | ErrorType::ConnectNoRoute
            | ErrorType::ConnectProxyFailure
            | ErrorType::ConnectError
            | ErrorType::TLSWantX509Lookup
            | ErrorType::TLSHandshakeFailure
            | ErrorType::TLSHandshakeTimedout
            | ErrorType::InvalidCert
            | ErrorType::HandshakeError
            | ErrorType::ReadError
            | ErrorType::WriteError
            | ErrorType::ReadTimedout
            | ErrorType::WriteTimedout
            | ErrorType::ConnectionClosed
            | ErrorType::H1Error
            | ErrorType::H2Error
            | ErrorType::InvalidH2
    )
}

fn downstream_error_is_request_outcome(error_type: &ErrorType) -> bool {
    matches!(
        error_type,
        ErrorType::InvalidHTTPHeader
            | ErrorType::H1Error
            | ErrorType::H2Error
            | ErrorType::InvalidH2
            | ErrorType::ReadError
            | ErrorType::WriteError
            | ErrorType::ReadTimedout
            | ErrorType::WriteTimedout
            | ErrorType::ConnectionClosed
    )
}

fn unset_error_is_request_outcome(error_type: &ErrorType, status: Option<u16>) -> bool {
    matches!(
        error_type,
        ErrorType::InvalidHTTPHeader
            | ErrorType::H1Error
            | ErrorType::H2Error
            | ErrorType::InvalidH2
            | ErrorType::ReadError
            | ErrorType::WriteError
            | ErrorType::ReadTimedout
            | ErrorType::WriteTimedout
            | ErrorType::ConnectionClosed
    ) || status.is_some_and(|status| (400..600).contains(&status))
}

fn status_label(status: u16) -> &'static str {
    match status {
        400 => "proxy: http_400",
        401 => "proxy: http_401",
        403 => "proxy: http_403",
        404 => "proxy: http_404",
        408 => "proxy: http_408",
        429 => "proxy: http_429",
        499 => "proxy: client_closed",
        500 => "proxy: http_500",
        502 => "proxy: http_502",
        503 => "proxy: http_503",
        504 => "proxy: http_504",
        status if (400..500).contains(&status) => "proxy: http_4xx",
        status if (500..600).contains(&status) => "proxy: http_5xx",
        _ => "proxy: request_error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_upstream_failures_are_request_outcomes() {
        for error_type in [
            ErrorType::ConnectTimedout,
            ErrorType::ReadTimedout,
            ErrorType::WriteTimedout,
            ErrorType::ConnectRefused,
            ErrorType::ConnectNoRoute,
            ErrorType::ConnectError,
        ] {
            let error = Error::new_up(error_type);
            assert!(is_request_outcome_error(&error, None));
        }
    }

    #[test]
    fn common_downstream_failures_are_request_outcomes() {
        for error_type in [
            ErrorType::ReadError,
            ErrorType::WriteError,
            ErrorType::ConnectionClosed,
            ErrorType::InvalidHTTPHeader,
        ] {
            let error = Error::new_down(error_type);
            assert!(is_request_outcome_error(&error, None));
        }
    }

    #[test]
    fn internal_failures_remain_process_log_events() {
        let error = Error::new_in(ErrorType::InternalError);
        assert!(!is_request_outcome_error(&error, Some(500)));
        assert!(should_emit_process_log(
            ProcessLogEventKind::RequestOutcome,
            ProcessLogSeverity::Error,
            Some(&error),
            Some(500)
        ));
    }

    #[test]
    fn labels_are_stable_for_access_logs() {
        let error = Error::new_up(ErrorType::ReadTimedout);
        assert_eq!(
            access_log_error_label(&error, Some(504)),
            "proxy: upstream_read_timeout"
        );

        let error = Error::new_down(ErrorType::ConnectionClosed);
        assert_eq!(
            access_log_error_label(&error, None),
            "proxy: downstream_closed"
        );
    }
}
