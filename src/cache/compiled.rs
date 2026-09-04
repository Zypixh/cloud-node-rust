use crate::compiled::CompiledPlanSet;
use crate::config_models::{
    HTTPCachePolicy, HTTPCacheRef, HTTPRequestCond, HTTPRequestCondGroup, HTTPRequestCondsConfig,
    ServerConfig, SizeCapacity, URLPattern,
};
use http::{HeaderMap, header::COOKIE};
use pingora_proxy::Session;
use regex::Regex;
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Clone)]
pub struct CacheEvalContext<'a> {
    pub session: &'a Session,
    pub scheme: &'a str,
    pub cache_key_scheme: Option<String>,
    pub cache_key_host: Option<String>,
    pub server: Option<Arc<ServerConfig>>,
    pub client_ip: Option<IpAddr>,
    pub client_port: Option<u16>,
    pub raw_remote_addr: Option<String>,
    pub start_timestamp_millis: Option<i64>,
    pub is_http3_bridge: bool,
    pub host: Option<String>,
    pub analyzed: Option<crate::metrics::analyzer::RequestStats>,
    pub response_status: Option<u16>,
    pub response_headers: Option<&'a HeaderMap>,
}

impl<'a> CacheEvalContext<'a> {
    pub fn new(session: &'a Session, scheme: &'a str) -> Self {
        Self {
            session,
            scheme,
            cache_key_scheme: None,
            cache_key_host: None,
            server: None,
            client_ip: None,
            client_port: None,
            raw_remote_addr: None,
            start_timestamp_millis: None,
            is_http3_bridge: false,
            host: None,
            analyzed: None,
            response_status: None,
            response_headers: None,
        }
    }

    pub fn with_response(mut self, status: u16, headers: &'a HeaderMap) -> Self {
        self.response_status = Some(status);
        self.response_headers = Some(headers);
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheMatchResult {
    Match,
    NoMatch,
    Deferred,
}

impl CacheMatchResult {
    pub fn from_bool(value: bool) -> Self {
        if value { Self::Match } else { Self::NoMatch }
    }

    pub fn is_request_candidate(self) -> bool {
        !matches!(self, Self::NoMatch)
    }

    pub fn is_match(self) -> bool {
        matches!(self, Self::Match)
    }
}

#[derive(Clone, Debug)]
pub struct CompiledWebCachePlan {
    pub is_on: bool,
    pub disable_policy_refs: bool,
    pub refs: Vec<Arc<CompiledCacheRef>>,
    pub policy: Option<Arc<CompiledCachePolicy>>,
}

impl CompiledWebCachePlan {
    pub fn compile(server: &ServerConfig) -> Option<Self> {
        let cache = server.web.as_ref()?.cache.as_ref()?;
        Some(Self {
            is_on: cache.is_on,
            disable_policy_refs: cache.disable_policy_refs,
            refs: cache
                .cache_refs
                .iter()
                .map(CompiledCacheRef::compile_arc)
                .collect(),
            policy: cache
                .cache_policy
                .as_ref()
                .map(CompiledCachePolicy::compile_arc),
        })
    }
}

#[derive(Clone, Debug)]
pub struct CompiledCachePolicy {
    pub raw: Arc<HTTPCachePolicy>,
    pub refs: Vec<Arc<CompiledCacheRef>>,
    pub add_status_header: bool,
    pub add_age_header: bool,
    pub allow_chunked_encoding: bool,
    pub force_partial_content: bool,
    pub max_item_size_bytes: Option<i64>,
    pub max_size_bytes: Option<i64>,
}

impl CompiledCachePolicy {
    pub fn compile_arc(policy: &Arc<HTTPCachePolicy>) -> Arc<Self> {
        policy.compile_url_patterns();
        Arc::new(Self {
            raw: Arc::clone(policy),
            refs: policy
                .cache_refs
                .iter()
                .map(CompiledCacheRef::compile_arc)
                .collect(),
            add_status_header: policy.add_status_header,
            add_age_header: policy.add_age_header,
            allow_chunked_encoding: policy.allow_chunked_encoding,
            force_partial_content: policy.force_partial_content,
            max_item_size_bytes: compile_size_capacity(policy.max_item_size.as_ref()),
            max_size_bytes: compile_size_capacity(policy.max_size.as_ref()),
        })
    }
}

#[derive(Clone, Debug)]
pub struct CompiledCacheRef {
    pub raw: Arc<HTTPCacheRef>,
    pub is_on: bool,
    pub is_reverse: bool,
    only_url_patterns: Vec<URLPattern>,
    except_url_patterns: Vec<URLPattern>,
    request_program: CompiledCacheRequestProgram,
    pub key_template: Option<CompiledCacheTemplate>,
    pub child_policy: Option<Arc<CompiledCachePolicy>>,
    pub response_policy: CompiledCacheResponsePolicy,
}

impl CompiledCacheRef {
    pub fn compile_arc(cache_ref: &Arc<HTTPCacheRef>) -> Arc<Self> {
        cache_ref.compile_url_patterns();
        Arc::new(Self {
            raw: Arc::clone(cache_ref),
            is_on: cache_ref.is_on,
            is_reverse: cache_ref.is_reverse,
            only_url_patterns: cache_ref.only_url_patterns.clone(),
            except_url_patterns: cache_ref.except_url_patterns.clone(),
            request_program: CompiledCacheRequestProgram::compile(
                cache_ref.conds.as_ref(),
                cache_ref.simple_cond.as_ref(),
            ),
            key_template: cache_ref
                .key
                .as_deref()
                .filter(|key| !key.is_empty())
                .map(CompiledCacheTemplate::compile),
            child_policy: cache_ref
                .cache_policy
                .as_ref()
                .map(CompiledCachePolicy::compile_arc),
            response_policy: CompiledCacheResponsePolicy::compile(cache_ref),
        })
    }

    fn matches_request_with_context(&self, ctx: &CacheEvalContext<'_>) -> bool {
        let path = ctx.session.req_header().uri.path();
        let mut url = None;
        if !self.except_url_patterns.is_empty()
            && self.except_url_patterns.iter().any(|pattern| {
                pattern.matches(path)
                    || pattern.matches(cache_match_url(&mut url, ctx.session, ctx.scheme, path))
            })
        {
            return false;
        }
        if !self.only_url_patterns.is_empty()
            && !self.only_url_patterns.iter().any(|pattern| {
                pattern.matches(path)
                    || pattern.matches(cache_match_url(&mut url, ctx.session, ctx.scheme, path))
            })
        {
            return false;
        }
        self.request_program
            .request_match_with_context(ctx)
            .is_request_candidate()
    }
}

#[derive(Clone, Debug)]
pub enum CompiledCacheRequestProgram {
    Always,
    Groups {
        connector: CacheConnector,
        groups: Vec<CompiledCacheCondGroup>,
    },
    Simple(CompiledCacheCond),
}

impl CompiledCacheRequestProgram {
    fn compile(config: Option<&HTTPRequestCondsConfig>, simple: Option<&HTTPRequestCond>) -> Self {
        if let Some(config) = config
            && config.is_on
            && !config.groups.is_empty()
        {
            return Self::Groups {
                connector: CacheConnector::compile(&config.connector),
                groups: config
                    .groups
                    .iter()
                    .map(CompiledCacheCondGroup::compile)
                    .collect(),
            };
        }
        if let Some(simple) = simple {
            return Self::Simple(CompiledCacheCond::compile(simple));
        }
        Self::Always
    }

    fn request_match_with_context(&self, ctx: &CacheEvalContext<'_>) -> CacheMatchResult {
        match self {
            Self::Always => CacheMatchResult::Match,
            Self::Groups { connector, groups } => match connector {
                CacheConnector::And => {
                    let mut deferred = false;
                    for group in groups {
                        match group.request_match_with_context(ctx) {
                            CacheMatchResult::Match => {}
                            CacheMatchResult::Deferred => deferred = true,
                            CacheMatchResult::NoMatch => return CacheMatchResult::NoMatch,
                        }
                    }
                    if deferred {
                        CacheMatchResult::Deferred
                    } else {
                        CacheMatchResult::Match
                    }
                }
                CacheConnector::Or => {
                    let mut deferred = false;
                    for group in groups {
                        match group.request_match_with_context(ctx) {
                            CacheMatchResult::Match => return CacheMatchResult::Match,
                            CacheMatchResult::Deferred => deferred = true,
                            CacheMatchResult::NoMatch => {}
                        }
                    }
                    if deferred {
                        CacheMatchResult::Deferred
                    } else {
                        CacheMatchResult::NoMatch
                    }
                }
            },
            Self::Simple(cond) => cond.request_match_with_context(ctx),
        }
    }

    pub fn matches_with_context(&self, ctx: &CacheEvalContext<'_>) -> bool {
        match self {
            Self::Always => true,
            Self::Groups { connector, groups } => match connector {
                CacheConnector::And => groups.iter().all(|group| group.matches_with_context(ctx)),
                CacheConnector::Or => groups.iter().any(|group| group.matches_with_context(ctx)),
            },
            Self::Simple(cond) => cond.matches_with_context(ctx),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CompiledCacheCondGroup {
    is_on: bool,
    connector: CacheConnector,
    conds: Vec<CompiledCacheCond>,
}

impl CompiledCacheCondGroup {
    fn compile(group: &HTTPRequestCondGroup) -> Self {
        Self {
            is_on: group.is_on,
            connector: CacheConnector::compile(&group.connector),
            conds: group.conds.iter().map(CompiledCacheCond::compile).collect(),
        }
    }

    fn request_match_with_context(&self, ctx: &CacheEvalContext<'_>) -> CacheMatchResult {
        if !self.is_on || self.conds.is_empty() {
            return CacheMatchResult::Match;
        }
        match self.connector {
            CacheConnector::And => {
                let mut deferred = false;
                for cond in &self.conds {
                    match cond.request_match_with_context(ctx) {
                        CacheMatchResult::Match => {}
                        CacheMatchResult::Deferred => deferred = true,
                        CacheMatchResult::NoMatch => return CacheMatchResult::NoMatch,
                    }
                }
                if deferred {
                    CacheMatchResult::Deferred
                } else {
                    CacheMatchResult::Match
                }
            }
            CacheConnector::Or => {
                let mut deferred = false;
                for cond in &self.conds {
                    match cond.request_match_with_context(ctx) {
                        CacheMatchResult::Match => return CacheMatchResult::Match,
                        CacheMatchResult::Deferred => deferred = true,
                        CacheMatchResult::NoMatch => {}
                    }
                }
                if deferred {
                    CacheMatchResult::Deferred
                } else {
                    CacheMatchResult::NoMatch
                }
            }
        }
    }

    fn matches_with_context(&self, ctx: &CacheEvalContext<'_>) -> bool {
        if !self.is_on || self.conds.is_empty() {
            return true;
        }
        match self.connector {
            CacheConnector::And => self.conds.iter().all(|cond| cond.matches_with_context(ctx)),
            CacheConnector::Or => self.conds.iter().any(|cond| cond.matches_with_context(ctx)),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum CacheConnector {
    And,
    Or,
}

impl CacheConnector {
    pub fn compile(value: &str) -> Self {
        if value == "and" { Self::And } else { Self::Or }
    }
}

#[derive(Clone, Debug)]
pub struct CompiledCacheCond {
    is_request: bool,
    variable: CacheVariable,
    operator: CacheOperator,
    reverse: bool,
}

impl CompiledCacheCond {
    fn compile(cond: &HTTPRequestCond) -> Self {
        Self {
            is_request: cond.is_request,
            variable: CacheVariable::compile(&cond.param),
            operator: CacheOperator::compile(&cond.operator, &cond.value, cond.is_case_insensitive),
            reverse: cond.is_reverse,
        }
    }

    fn request_match_with_context(&self, ctx: &CacheEvalContext<'_>) -> CacheMatchResult {
        if !self.is_request || self.variable.is_response_known() {
            return CacheMatchResult::Deferred;
        }
        CacheMatchResult::from_bool(self.matches_with_context(ctx))
    }

    fn matches_with_context(&self, ctx: &CacheEvalContext<'_>) -> bool {
        let value = self.variable.resolve_with_context(ctx);
        let matched = self.operator.matches_with_context(&value, ctx);
        if self.reverse { !matched } else { matched }
    }
}

#[derive(Clone, Debug)]
pub enum CacheOperator {
    Regex(Option<Arc<Regex>>),
    NotRegex(Option<Arc<Regex>>),
    Wildcard(Option<Arc<Regex>>),
    NotWildcard(Option<Arc<Regex>>),
    Eq(String, bool),
    Neq(String, bool),
    Prefix(String, bool),
    Suffix(String, bool),
    Contains(String, bool),
    NotContains(String, bool),
    In(Vec<String>, bool),
    NotIn(Vec<String>, bool),
    FileExt(Vec<String>),
    MimeType(Vec<MimeMatcher>),
    Number(NumberOperator),
    VersionRange(Option<String>, Option<String>),
    Ip(IpOperator),
    NeverMatch,
}

#[derive(Clone, Debug)]
pub struct MimeMatcher {
    type_part: String,
    subtype_part: Option<String>,
}

#[derive(Clone, Debug)]
pub enum NumberOperator {
    EqInt(i64),
    EqFloat(f64),
    Gt(f64),
    Gte(f64),
    Lt(f64),
    Lte(f64),
    Mod { divisor: u64, remainder: u64 },
}

#[derive(Clone, Debug)]
pub enum IpOperator {
    Eq(IpAddr),
    Gt(IpAddr),
    Gte(IpAddr),
    Lt(IpAddr),
    Lte(IpAddr),
    Range(IpAddr, IpAddr),
    Mod { divisor: u128, remainder: u128 },
}

impl CacheOperator {
    pub fn compile(operator: &str, expected: &str, case_insensitive: bool) -> Self {
        match normalize_operator(operator).as_str() {
            "matches" | "regexp" => Self::Regex(compile_regex(expected, case_insensitive)),
            "notmatches" | "notregexp" => Self::NotRegex(compile_regex(expected, case_insensitive)),
            "wildcardmatch" => Self::Wildcard(compile_wildcard(expected, case_insensitive)),
            "wildcardnotmatch" | "notwildcardmatch" => {
                Self::NotWildcard(compile_wildcard(expected, case_insensitive))
            }
            "eq" | "equals" => Self::Eq(expected.to_string(), case_insensitive),
            "neq" | "notequals" | "not" => Self::Neq(expected.to_string(), case_insensitive),
            "prefix" | "hasprefix" => Self::Prefix(expected.to_string(), case_insensitive),
            "suffix" | "hassuffix" => Self::Suffix(expected.to_string(), case_insensitive),
            "contains" | "containsstring" => Self::Contains(expected.to_string(), case_insensitive),
            "notcontains" => Self::NotContains(expected.to_string(), case_insensitive),
            "in" => Self::In(parse_list_values(expected), case_insensitive),
            "notin" => Self::NotIn(parse_list_values(expected), case_insensitive),
            "fileext" | "fileextension" | "fileextensions" => {
                Self::FileExt(parse_extension_values(expected))
            }
            "mimetype" => compile_mime_operator(expected),
            "versionrange" => compile_version_range(expected),
            "eqint" => expected
                .parse::<i64>()
                .map(|value| Self::Number(NumberOperator::EqInt(value)))
                .unwrap_or(Self::NeverMatch),
            "eqfloat" => expected
                .parse::<f64>()
                .ok()
                .filter(|value| value.is_finite())
                .map(|value| Self::Number(NumberOperator::EqFloat(value)))
                .unwrap_or(Self::NeverMatch),
            "gt" => compile_number_compare(expected, NumberCompare::Gt),
            "gte" => compile_number_compare(expected, NumberCompare::Gte),
            "lt" => compile_number_compare(expected, NumberCompare::Lt),
            "lte" => compile_number_compare(expected, NumberCompare::Lte),
            "mod10" => compile_mod_operator("10", expected),
            "mod100" => compile_mod_operator("100", expected),
            "mod" => compile_dynamic_mod_operator(expected),
            "eqip" => compile_ip_operator(expected, IpCompare::Eq),
            "gtip" => compile_ip_operator(expected, IpCompare::Gt),
            "gteip" => compile_ip_operator(expected, IpCompare::Gte),
            "ltip" => compile_ip_operator(expected, IpCompare::Lt),
            "lteip" => compile_ip_operator(expected, IpCompare::Lte),
            "iprange" => compile_ip_range_operator(expected),
            "ipmod10" => compile_ip_mod_operator("10", expected),
            "ipmod100" => compile_ip_mod_operator("100", expected),
            "ipmod" => compile_dynamic_ip_mod_operator(expected),
            _ => Self::NeverMatch,
        }
    }

    pub fn matches(&self, value: &str, session: &Session, scheme: &str) -> bool {
        let ctx = CacheEvalContext::new(session, scheme);
        self.matches_with_context(value, &ctx)
    }

    pub fn matches_with_context(&self, value: &str, ctx: &CacheEvalContext<'_>) -> bool {
        match self {
            Self::Regex(re) => re.as_ref().is_some_and(|re| re.is_match(value)),
            Self::NotRegex(re) => re.as_ref().is_some_and(|re| !re.is_match(value)),
            Self::Wildcard(re) => re.as_ref().is_some_and(|re| re.is_match(value)),
            Self::NotWildcard(re) => re.as_ref().is_some_and(|re| !re.is_match(value)),
            Self::Eq(expected, ci) => eq_value(value, expected, *ci),
            Self::Neq(expected, ci) => !eq_value(value, expected, *ci),
            Self::Prefix(expected, ci) => starts_with_value(value, expected, *ci),
            Self::Suffix(expected, ci) => ends_with_value(value, expected, *ci),
            Self::Contains(expected, ci) => contains_value(value, expected, *ci),
            Self::NotContains(expected, ci) => {
                !expected.is_empty() && !contains_value(value, expected, *ci)
            }
            Self::In(values, ci) => value_in_list(value, values, *ci),
            Self::NotIn(values, ci) => !values.is_empty() && !value_in_list(value, values, *ci),
            Self::FileExt(values) => {
                let extension = CacheVariable::RequestPathLowerExtension.resolve_with_context(ctx);
                !extension.is_empty() && values.iter().any(|item| item == &extension)
            }
            Self::MimeType(matchers) => mime_matches(value, matchers),
            Self::Number(operator) => number_matches(value, operator),
            Self::VersionRange(min, max) => {
                version_range_matches(value, min.as_deref(), max.as_deref())
            }
            Self::Ip(operator) => ip_matches(value, operator),
            Self::NeverMatch => false,
        }
    }
}

#[derive(Clone, Debug)]
pub enum CacheVariable {
    Literal(String),
    CloudVersion,
    RequestPath,
    RequestPathExtension,
    RequestPathLowerExtension,
    RequestFilename,
    RequestMethod,
    RequestLength,
    RequestUri,
    RequestUrl,
    Host,
    ServerName,
    ServerPort,
    Scheme,
    Proto,
    IsArgs,
    Args,
    RemoteAddr,
    RawRemoteAddr,
    RemotePort,
    RemoteUser,
    Referer,
    RefererHost,
    UserAgent,
    ContentType,
    Cookies,
    Headers,
    Timestamp,
    Msec,
    TimeIso8601,
    TimeLocal,
    GeoCountryName,
    GeoCountryId,
    GeoProvinceName,
    GeoProvinceId,
    GeoCityName,
    GeoCityId,
    IspName,
    IspId,
    BrowserName,
    BrowserVersion,
    BrowserOsName,
    BrowserOsVersion,
    BrowserIsMobile,
    ResponseContentType,
    ResponseStatus,
    ResponseHeader(String),
    Arg(String),
    Header(String),
    Cookie(String),
    Unknown,
}

impl CacheVariable {
    pub fn compile(param: &str) -> Self {
        let Some(inner) = param
            .strip_prefix("${")
            .and_then(|value| value.strip_suffix('}'))
        else {
            return Self::Literal(param.to_string());
        };
        Self::compile_inner(inner)
    }

    pub fn compile_inner(inner: &str) -> Self {
        match inner {
            "cloudVersion" => Self::CloudVersion,
            "requestPath" => Self::RequestPath,
            "requestPathExtension" => Self::RequestPathExtension,
            "requestPathLowerExtension" => Self::RequestPathLowerExtension,
            "requestFilename" => Self::RequestFilename,
            "requestMethod" => Self::RequestMethod,
            "requestLength" => Self::RequestLength,
            "requestURI" => Self::RequestUri,
            "requestURL" | "requestUrl" => Self::RequestUrl,
            "host" | "requestHost" => Self::Host,
            "serverName" => Self::ServerName,
            "serverPort" => Self::ServerPort,
            "scheme" => Self::Scheme,
            "proto" => Self::Proto,
            "isArgs" => Self::IsArgs,
            "args" => Self::Args,
            "remoteAddr" => Self::RemoteAddr,
            "rawRemoteAddr" => Self::RawRemoteAddr,
            "remotePort" => Self::RemotePort,
            "remoteUser" => Self::RemoteUser,
            "referer" => Self::Referer,
            "referer.host" | "refererHost" => Self::RefererHost,
            "userAgent" | "httpUserAgent" => Self::UserAgent,
            "contentType" => Self::ContentType,
            "cookies" => Self::Cookies,
            "headers" => Self::Headers,
            "timestamp" => Self::Timestamp,
            "msec" => Self::Msec,
            "timeISO8601" => Self::TimeIso8601,
            "timeLocal" => Self::TimeLocal,
            "geo.country.name" => Self::GeoCountryName,
            "geo.country.id" => Self::GeoCountryId,
            "geo.province.name" => Self::GeoProvinceName,
            "geo.province.id" => Self::GeoProvinceId,
            "geo.city.name" => Self::GeoCityName,
            "geo.city.id" => Self::GeoCityId,
            "isp.name" => Self::IspName,
            "isp.id" => Self::IspId,
            "browser.name" => Self::BrowserName,
            "browser.version" => Self::BrowserVersion,
            "browser.os.name" => Self::BrowserOsName,
            "browser.os.version" => Self::BrowserOsVersion,
            "browser.isMobile" => Self::BrowserIsMobile,
            "response.contentType" | "responseContentType" => Self::ResponseContentType,
            "response.status" | "status" => Self::ResponseStatus,
            _ => prefixed_variable_arg(inner, &["response.header", "responseHeader"])
                .map(|key| Self::ResponseHeader(key.to_string()))
                .or_else(|| {
                    prefixed_variable_arg(inner, &["arg", "requestArg"])
                        .map(|key| Self::Arg(key.to_string()))
                })
                .or_else(|| {
                    prefixed_variable_arg(inner, &["header", "requestHeader"])
                        .map(|key| Self::Header(key.to_string()))
                })
                .or_else(|| {
                    prefixed_variable_arg(inner, &["cookie", "requestCookie"])
                        .map(|key| Self::Cookie(key.to_string()))
                })
                .unwrap_or(Self::Unknown),
        }
    }

    pub fn resolve(&self, session: &Session, scheme: &str) -> String {
        let ctx = CacheEvalContext::new(session, scheme);
        self.resolve_with_context(&ctx)
    }

    pub fn is_response_known(&self) -> bool {
        matches!(
            self,
            Self::ResponseContentType | Self::ResponseStatus | Self::ResponseHeader(_)
        )
    }

    pub fn resolve_with_context(&self, ctx: &CacheEvalContext<'_>) -> String {
        match self {
            Self::Literal(value) => value.clone(),
            Self::CloudVersion => env!("CARGO_PKG_VERSION").to_string(),
            Self::RequestPath => ctx.session.req_header().uri.path().to_string(),
            Self::RequestPathExtension => request_path_extension(ctx.session, false),
            Self::RequestPathLowerExtension => request_path_extension(ctx.session, true),
            Self::RequestFilename => request_filename(ctx.session),
            Self::RequestMethod => ctx.session.req_header().method.to_string(),
            Self::RequestLength => request_length(ctx.session).to_string(),
            Self::RequestUri => request_uri(ctx.session),
            Self::RequestUrl => request_url(ctx),
            Self::Host => ctx
                .cache_key_host
                .clone()
                .unwrap_or_else(|| request_host(ctx.session)),
            Self::ServerName => ctx
                .server
                .as_ref()
                .map(|server| server.get_first_host())
                .filter(|value| !value.is_empty())
                .or_else(|| ctx.host.clone())
                .unwrap_or_else(|| request_host(ctx.session)),
            Self::ServerPort => downstream_local_port(ctx.session)
                .map(|port| port.to_string())
                .unwrap_or_default(),
            Self::Scheme => ctx
                .cache_key_scheme
                .clone()
                .unwrap_or_else(|| ctx.scheme.to_string()),
            Self::Proto => request_proto(ctx.session, ctx.is_http3_bridge),
            Self::IsArgs => {
                if ctx.session.req_header().uri.query().is_some() {
                    "?".to_string()
                } else {
                    String::new()
                }
            }
            Self::Args => ctx
                .session
                .req_header()
                .uri
                .query()
                .unwrap_or("")
                .to_string(),
            Self::RemoteAddr => ctx
                .client_ip
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| crate::client_ip::raw_remote_addr(ctx.session)),
            Self::RawRemoteAddr => raw_remote_ip(ctx),
            Self::RemotePort => ctx
                .client_port
                .map(|port| port.to_string())
                .or_else(|| {
                    let port = crate::client_ip::peer_remote_port(ctx.session);
                    (port > 0).then(|| port.to_string())
                })
                .unwrap_or_default(),
            Self::RemoteUser => String::new(),
            Self::Referer => header_value(ctx.session, "referer"),
            Self::RefererHost => referer_host(ctx.session),
            Self::UserAgent => header_value(ctx.session, "user-agent"),
            Self::ContentType => header_value(ctx.session, "content-type"),
            Self::Cookies => header_value(ctx.session, "cookie"),
            Self::Headers => request_headers(ctx.session),
            Self::Timestamp => ctx
                .start_timestamp_millis
                .map(|millis| (millis / 1000).to_string())
                .unwrap_or_default(),
            Self::Msec => ctx
                .start_timestamp_millis
                .map(|millis| format!("{:.3}", millis as f64 / 1000.0))
                .unwrap_or_default(),
            Self::TimeIso8601 => ctx
                .start_timestamp_millis
                .map(|millis| {
                    crate::utils::time::local_from_timestamp_millis(millis)
                        .format("%Y-%m-%dT%H:%M:%S%.3f%:z")
                        .to_string()
                })
                .unwrap_or_default(),
            Self::TimeLocal => ctx
                .start_timestamp_millis
                .map(|millis| {
                    crate::utils::time::local_from_timestamp_millis(millis)
                        .format("%d/%b/%Y:%H:%M:%S %z")
                        .to_string()
                })
                .unwrap_or_default(),
            Self::GeoCountryName => request_stats(ctx)
                .and_then(|stats| stats.geo.map(|geo| geo.country.to_string()))
                .unwrap_or_default(),
            Self::GeoCountryId => request_stats(ctx)
                .and_then(|stats| stats.geo.map(|geo| geo.country_id.to_string()))
                .unwrap_or_default(),
            Self::GeoProvinceName => request_stats(ctx)
                .and_then(|stats| stats.geo.map(|geo| geo.region.to_string()))
                .unwrap_or_default(),
            Self::GeoProvinceId => request_stats(ctx)
                .and_then(|stats| stats.geo.map(|geo| geo.region_id.to_string()))
                .unwrap_or_default(),
            Self::GeoCityName => request_stats(ctx)
                .and_then(|stats| stats.geo.map(|geo| geo.city.to_string()))
                .unwrap_or_default(),
            Self::GeoCityId => request_stats(ctx)
                .and_then(|stats| stats.geo.map(|geo| geo.city_id.to_string()))
                .unwrap_or_default(),
            Self::IspName => request_stats(ctx)
                .and_then(|stats| stats.geo.map(|geo| geo.provider.to_string()))
                .unwrap_or_default(),
            Self::IspId => String::new(),
            Self::BrowserName => request_stats(ctx)
                .map(|stats| stats.browser.to_string())
                .unwrap_or_default(),
            Self::BrowserVersion => String::new(),
            Self::BrowserOsName => request_stats(ctx)
                .map(|stats| stats.os.to_string())
                .unwrap_or_default(),
            Self::BrowserOsVersion => String::new(),
            Self::BrowserIsMobile => browser_is_mobile(ctx).to_string(),
            Self::ResponseContentType => response_header_value(ctx, "content-type"),
            Self::ResponseStatus => ctx
                .response_status
                .map(|status| status.to_string())
                .unwrap_or_default(),
            Self::ResponseHeader(key) => response_header_value(ctx, key),
            Self::Arg(key) => query_param(ctx.session, key),
            Self::Header(key) => header_value(ctx.session, key),
            Self::Cookie(key) => cookie_value(ctx.session, key),
            Self::Unknown => String::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CompiledCacheResponsePolicy {
    methods: Vec<String>,
    statuses: Vec<i32>,
    min_size_bytes: Option<i64>,
    max_size_bytes: Option<i64>,
    skip_cache_control_values: Vec<String>,
    allow_chunked_encoding: bool,
    allow_partial_content: bool,
    force_partial_content: bool,
    enable_reading_origin_async: bool,
    ttl_seconds: u64,
    force_ttl_seconds: Option<u64>,
    auto_expires: bool,
    overwrite_expires: bool,
}

impl CompiledCacheResponsePolicy {
    fn compile(cache_ref: &HTTPCacheRef) -> Self {
        let force_ttl_seconds = if cache_ref
            .expires_time
            .as_ref()
            .is_some_and(|expires| expires.is_on)
        {
            cache_ref
                .expires_time
                .as_ref()
                .and_then(|expires| expires.duration.as_ref())
                .map(crate::config_models::parse_life_to_seconds)
                .filter(|seconds| *seconds > 0)
        } else {
            cache_ref
                .life
                .as_ref()
                .map(crate::config_models::parse_life_to_seconds)
                .filter(|seconds| *seconds > 0)
        };
        Self {
            methods: cache_ref.methods.clone(),
            statuses: cache_ref.status.clone(),
            min_size_bytes: compile_size_capacity(cache_ref.min_size.as_ref()),
            max_size_bytes: compile_size_capacity(cache_ref.max_size.as_ref()),
            skip_cache_control_values: cache_ref
                .skip_cache_control_values
                .iter()
                .filter(|value| !value.is_empty())
                .map(|value| value.to_lowercase())
                .collect(),
            allow_chunked_encoding: cache_ref.allow_chunked_encoding,
            allow_partial_content: cache_ref.allow_partial_content,
            force_partial_content: cache_ref.force_partial_content,
            enable_reading_origin_async: cache_ref.enable_reading_origin_async,
            ttl_seconds: cache_ref
                .life
                .as_ref()
                .map(crate::config_models::parse_life_to_seconds)
                .unwrap_or(3600),
            force_ttl_seconds,
            auto_expires: cache_ref
                .expires_time
                .as_ref()
                .map(|expires| expires.is_on && expires.auto_calculate)
                .unwrap_or(false),
            overwrite_expires: cache_ref
                .expires_time
                .as_ref()
                .map(|expires| expires.overwrite)
                .unwrap_or(false),
        }
    }

    pub fn ttl_seconds(&self) -> u64 {
        self.ttl_seconds
    }

    pub fn force_ttl_seconds(&self) -> Option<u64> {
        self.force_ttl_seconds
    }

    pub fn auto_expires(&self) -> bool {
        self.auto_expires
    }

    pub fn overwrite_expires(&self) -> bool {
        self.overwrite_expires
    }

    fn allows_method_status(
        &self,
        status: u16,
        method: &str,
        _force_partial_content: bool,
    ) -> bool {
        if !crate::cache::status_allows_shared_cache_with_error_policy(
            status,
            self.error_status_allowed(status),
        ) {
            return false;
        }
        let safe_method = method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD");
        let method_allowed = safe_method
            && (self.methods.is_empty()
                || self
                    .methods
                    .iter()
                    .any(|item| item.eq_ignore_ascii_case(method)));
        if !method_allowed {
            return false;
        }

        let partial_content_allowed = self.allow_partial_content || self.statuses.contains(&206);
        if status == 206 && !partial_content_allowed {
            return false;
        }
        if self.statuses.is_empty() {
            true
        } else {
            self.statuses.contains(&(status as i32)) || (status == 206 && partial_content_allowed)
        }
    }

    pub fn allows_chunked_encoding(&self, policy: Option<&CompiledCachePolicy>) -> bool {
        self.allow_chunked_encoding
            || policy
                .map(|policy| policy.allow_chunked_encoding)
                .unwrap_or(false)
    }

    pub fn force_partial_content(&self, policy: Option<&CompiledCachePolicy>) -> bool {
        self.force_partial_content
            || policy
                .map(|policy| policy.force_partial_content)
                .unwrap_or(false)
    }

    pub fn enable_reading_origin_async(&self) -> bool {
        self.enable_reading_origin_async
    }

    fn should_cache_response(
        &self,
        _policy: Option<&CompiledCachePolicy>,
        status: u16,
        method: &str,
        headers: &HeaderMap,
        body_size: usize,
        force_partial_content: bool,
        skip_size_checks: bool,
        req_headers: &HeaderMap,
    ) -> bool {
        if !crate::cache::request_headers_allow_shared_cache(method, req_headers)
            || !crate::cache::response_headers_allow_shared_cache(headers)
        {
            return false;
        }
        if !self.allows_method_status(status, method, force_partial_content) {
            return false;
        }
        if !skip_size_checks {
            if self
                .min_size_bytes
                .is_some_and(|min_size| crate::cache::body_size_below_limit(body_size, min_size))
            {
                return false;
            }
            if self
                .max_size_bytes
                .is_some_and(|max_size| crate::cache::body_size_exceeds_limit(body_size, max_size))
            {
                return false;
            }
        }
        if crate::cache::cache_control_headers_have_skipped_value(
            headers,
            &self.skip_cache_control_values,
        ) {
            return false;
        }
        true
    }

    pub fn max_object_size_bytes(&self, policy: Option<&CompiledCachePolicy>) -> Option<i64> {
        let mut max_bytes = i64::MAX;
        if let Some(policy) = policy {
            if let Some(size) = policy.max_item_size_bytes.filter(|size| *size > 0) {
                max_bytes = size;
            }
            if let Some(size) = policy
                .max_size_bytes
                .filter(|size| *size > 0 && *size < max_bytes)
            {
                max_bytes = size;
            }
        }
        if let Some(size) = self
            .max_size_bytes
            .filter(|size| *size > 0 && *size < max_bytes)
        {
            max_bytes = size;
        }
        (max_bytes != i64::MAX).then_some(max_bytes)
    }

    pub fn allows_partial_content(&self) -> bool {
        self.allow_partial_content || self.statuses.contains(&206)
    }

    pub fn error_status_allowed(&self, status: u16) -> bool {
        status >= 500 && self.statuses.contains(&(status as i32))
    }
}

#[derive(Clone, Debug)]
pub struct CompiledCacheTemplate {
    parts: Vec<CacheTemplatePart>,
}

impl CompiledCacheTemplate {
    pub fn compile(template: &str) -> Self {
        let mut parts = Vec::new();
        let mut rest = template;
        while let Some(start) = rest.find("${") {
            if start > 0 {
                parts.push(CacheTemplatePart::Literal(rest[..start].to_string()));
            }
            let after_start = &rest[start + 2..];
            let Some(end) = after_start.find('}') else {
                parts.push(CacheTemplatePart::Literal(rest[start..].to_string()));
                rest = "";
                break;
            };
            let inner = &after_start[..end];
            parts.push(CacheTemplatePart::Variable(CacheVariable::compile_inner(
                inner,
            )));
            rest = &after_start[end + 1..];
        }
        if !rest.is_empty() {
            parts.push(CacheTemplatePart::Literal(rest.to_string()));
        }
        Self { parts }
    }

    pub fn format(&self, session: &Session, scheme: &str) -> String {
        let ctx = CacheEvalContext::new(session, scheme);
        self.format_with_context(&ctx)
    }

    pub fn format_with_context(&self, ctx: &CacheEvalContext<'_>) -> String {
        let mut value = String::new();
        for part in &self.parts {
            match part {
                CacheTemplatePart::Literal(part) => value.push_str(part),
                CacheTemplatePart::Variable(variable) => {
                    value.push_str(&variable.resolve_with_context(ctx))
                }
            }
        }
        value
    }
}

#[derive(Clone, Debug)]
pub enum CacheTemplatePart {
    Literal(String),
    Variable(CacheVariable),
}

#[derive(Clone)]
pub struct CompiledCacheMatch {
    pub cache_ref: Arc<HTTPCacheRef>,
    pub cache_policy: Option<Arc<HTTPCachePolicy>>,
    pub compiled_ref: Arc<CompiledCacheRef>,
    pub compiled_policy: Option<Arc<CompiledCachePolicy>>,
}

pub enum CompiledCacheSelection {
    NoPlan,
    NoMatch,
    Matched(CompiledCacheMatch),
}

pub fn select_cache_ref_compiled(
    plans: &CompiledPlanSet,
    server_id: i64,
    session: &Session,
    scheme: &str,
) -> Option<CompiledCacheMatch> {
    let ctx = CacheEvalContext::new(session, scheme);
    match select_cache_ref_compiled_with_context(plans, server_id, &ctx) {
        CompiledCacheSelection::Matched(matched) => Some(matched),
        CompiledCacheSelection::NoPlan | CompiledCacheSelection::NoMatch => None,
    }
}

pub fn select_cache_ref_compiled_with_state(
    plans: &CompiledPlanSet,
    server_id: i64,
    session: &Session,
    scheme: &str,
) -> CompiledCacheSelection {
    let ctx = CacheEvalContext::new(session, scheme);
    select_cache_ref_compiled_with_context(plans, server_id, &ctx)
}

pub fn select_cache_ref_compiled_with_context(
    plans: &CompiledPlanSet,
    server_id: i64,
    ctx: &CacheEvalContext<'_>,
) -> CompiledCacheSelection {
    let Some(server_plan) = plans.server_cache.get(&server_id) else {
        return CompiledCacheSelection::NoPlan;
    };
    if !server_plan.is_on {
        return CompiledCacheSelection::NoMatch;
    }
    if let Some(matched) = select_from_refs(&server_plan.refs, None, ctx) {
        return CompiledCacheSelection::Matched(matched);
    }
    if server_plan.disable_policy_refs {
        return CompiledCacheSelection::NoMatch;
    }
    if let Some(policy) = &server_plan.policy {
        return select_from_refs(&policy.refs, Some(Arc::clone(policy)), ctx)
            .map(CompiledCacheSelection::Matched)
            .unwrap_or(CompiledCacheSelection::NoMatch);
    }
    for policy in &plans.global_cache {
        if let Some(matched) = select_from_refs(&policy.refs, Some(Arc::clone(policy)), ctx) {
            return CompiledCacheSelection::Matched(matched);
        }
    }
    CompiledCacheSelection::NoMatch
}

fn select_from_refs(
    refs: &[Arc<CompiledCacheRef>],
    policy: Option<Arc<CompiledCachePolicy>>,
    ctx: &CacheEvalContext<'_>,
) -> Option<CompiledCacheMatch> {
    refs.iter()
        .filter(|cache_ref| cache_ref.is_on)
        .find(|cache_ref| cache_ref.matches_request_with_context(ctx))
        .map(|compiled_ref| {
            let cache_policy = compiled_ref
                .child_policy
                .as_ref()
                .map(|policy| Arc::clone(&policy.raw))
                .or_else(|| policy.as_ref().map(|policy| Arc::clone(&policy.raw)));
            CompiledCacheMatch {
                cache_ref: Arc::clone(&compiled_ref.raw),
                cache_policy,
                compiled_ref: Arc::clone(compiled_ref),
                compiled_policy: compiled_ref.child_policy.clone().or(policy),
            }
        })
}

pub fn should_cache_response_compiled(
    cache_ref: &CompiledCacheRef,
    policy: Option<&CompiledCachePolicy>,
    status: u16,
    method: &str,
    headers: &HeaderMap,
    body_size: usize,
    force_partial_content: bool,
    skip_size_checks: bool,
    req_headers: &HeaderMap,
) -> bool {
    cache_ref.response_policy.should_cache_response(
        policy,
        status,
        method,
        headers,
        body_size,
        force_partial_content,
        skip_size_checks,
        req_headers,
    )
}

pub fn cache_ref_response_conditions_match(
    cache_ref: &CompiledCacheRef,
    ctx: &CacheEvalContext<'_>,
) -> bool {
    cache_ref.request_program.matches_with_context(ctx)
}

pub fn cache_ref_allows_method_status_compiled(
    cache_ref: &CompiledCacheRef,
    status: u16,
    method: &str,
    force_partial_content: bool,
) -> bool {
    cache_ref
        .response_policy
        .allows_method_status(status, method, force_partial_content)
}

fn cache_match_url<'a>(
    url: &'a mut Option<String>,
    session: &Session,
    scheme: &str,
    path: &str,
) -> &'a str {
    url.get_or_insert_with(|| {
        let host = session
            .get_header("host")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        format!("{scheme}://{host}{path}")
    })
    .as_str()
}

fn request_path_extension(session: &Session, lower: bool) -> String {
    let ext = std::path::Path::new(session.req_header().uri.path())
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or_default();
    if ext.is_empty() {
        String::new()
    } else if lower {
        format!(".{}", ext.to_ascii_lowercase())
    } else {
        format!(".{ext}")
    }
}

fn request_filename(session: &Session) -> String {
    std::path::Path::new(session.req_header().uri.path())
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_string()
}

fn request_length(session: &Session) -> u64 {
    let header_bytes: usize = session
        .req_header()
        .headers
        .iter()
        .map(|(name, value)| name.as_str().len() + value.len() + 4)
        .sum();
    let body_bytes = session
        .get_header("content-length")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    header_bytes as u64 + body_bytes
}

fn request_uri(session: &Session) -> String {
    session
        .req_header()
        .uri
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| "/".to_string())
}

fn request_url(ctx: &CacheEvalContext<'_>) -> String {
    let scheme = ctx.cache_key_scheme.as_deref().unwrap_or(ctx.scheme);
    let host = ctx
        .cache_key_host
        .clone()
        .or_else(|| ctx.host.clone())
        .unwrap_or_else(|| request_host(ctx.session));
    format!("{scheme}://{host}{}", request_uri(ctx.session))
}

fn request_host(session: &Session) -> String {
    session
        .get_header("host")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(':').next().unwrap_or(value))
        .or_else(|| session.req_header().uri.host())
        .unwrap_or("")
        .to_string()
}

fn downstream_local_port(session: &Session) -> Option<u16> {
    session
        .downstream_session
        .digest()
        .and_then(|digest| digest.socket_digest.as_ref())
        .and_then(|socket| socket.local_addr())
        .and_then(|addr| addr.as_inet())
        .map(|inet| inet.port())
}

fn raw_remote_ip(ctx: &CacheEvalContext<'_>) -> String {
    let fallback = ctx
        .client_ip
        .unwrap_or_else(|| crate::client_ip::peer_socket_ip(ctx.session));
    ctx.raw_remote_addr
        .as_deref()
        .map(|raw| crate::client_ip::format_raw_remote_addr(raw, fallback))
        .unwrap_or_else(|| fallback.to_string())
}

fn request_proto(session: &Session, is_http3_bridge: bool) -> String {
    if is_http3_bridge {
        return "HTTP/3.0".to_string();
    }
    match session.req_header().version {
        http::Version::HTTP_10 => "HTTP/1.0".to_string(),
        http::Version::HTTP_11 => "HTTP/1.1".to_string(),
        http::Version::HTTP_2 => "HTTP/2.0".to_string(),
        http::Version::HTTP_3 => "HTTP/3.0".to_string(),
        _ => "HTTP/1.1".to_string(),
    }
}

fn referer_host(session: &Session) -> String {
    let referer = header_value(session, "referer");
    if referer.is_empty() {
        return String::new();
    }
    referer
        .parse::<http::Uri>()
        .ok()
        .and_then(|uri| uri.host().map(str::to_string))
        .unwrap_or_default()
}

fn request_headers(session: &Session) -> String {
    session
        .req_header()
        .headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| format!("{}: {}", name.as_str(), value))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn request_stats(ctx: &CacheEvalContext<'_>) -> Option<crate::metrics::analyzer::RequestStats> {
    ctx.analyzed.clone().or_else(|| {
        let ip = ctx.client_ip?;
        let ua = header_value(ctx.session, "user-agent");
        Some(crate::metrics::analyzer::analyze_request(ip, &ua))
    })
}

fn browser_is_mobile(ctx: &CacheEvalContext<'_>) -> &'static str {
    let ua = header_value(ctx.session, "user-agent").to_ascii_lowercase();
    if ua.contains("mobile")
        || ua.contains("android")
        || ua.contains("iphone")
        || ua.contains("ipad")
    {
        "1"
    } else {
        "0"
    }
}

fn prefixed_variable_arg<'a>(inner: &'a str, prefixes: &[&str]) -> Option<&'a str> {
    for prefix in prefixes {
        let Some(rest) = inner.strip_prefix(prefix) else {
            continue;
        };
        if let Some(value) = rest.strip_prefix(':').or_else(|| rest.strip_prefix('.')) {
            return Some(value);
        }
    }
    None
}

fn header_value(session: &Session, name: &str) -> String {
    session
        .get_header(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_string()
}

fn response_header_value(ctx: &CacheEvalContext<'_>, name: &str) -> String {
    ctx.response_headers
        .and_then(|headers| headers.get(name))
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_string()
}

fn query_param(session: &Session, name: &str) -> String {
    session
        .req_header()
        .uri
        .query()
        .and_then(|query| {
            query.split('&').find_map(|pair| {
                let (key, value) = pair.split_once('=')?;
                if key == name {
                    Some(value.to_string())
                } else {
                    None
                }
            })
        })
        .unwrap_or_default()
}

fn cookie_value(session: &Session, name: &str) -> String {
    session
        .req_header()
        .headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|cookies| cookies.split(';').map(str::trim))
        .find_map(|cookie| {
            let (key, value) = cookie.split_once('=')?;
            if key == name {
                Some(value.to_string())
            } else {
                None
            }
        })
        .unwrap_or_default()
}

fn normalize_operator(operator: &str) -> String {
    operator
        .trim()
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace() && *ch != '_' && *ch != '-')
        .flat_map(char::to_lowercase)
        .collect()
}

fn compile_regex(pattern: &str, case_insensitive: bool) -> Option<Arc<Regex>> {
    let pattern = if case_insensitive && !pattern.starts_with("(?i)") {
        format!("(?i){pattern}")
    } else {
        pattern.to_string()
    };
    Regex::new(&pattern).ok().map(Arc::new)
}

fn compile_wildcard(pattern: &str, case_insensitive: bool) -> Option<Arc<Regex>> {
    if pattern.is_empty() {
        return Regex::new("^$").ok().map(Arc::new);
    }
    let pattern = regex::escape(pattern).replace("\\*", ".*");
    let pattern = if case_insensitive {
        format!("(?i)^{pattern}$")
    } else {
        format!("^{pattern}$")
    };
    Regex::new(&pattern).ok().map(Arc::new)
}

fn parse_list_values(value: &str) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(value).unwrap_or_else(|_| {
        value
            .split(',')
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .collect()
    })
}

#[derive(Clone, Copy, Debug)]
enum NumberCompare {
    Gt,
    Gte,
    Lt,
    Lte,
}

#[derive(Clone, Copy, Debug)]
enum IpCompare {
    Eq,
    Gt,
    Gte,
    Lt,
    Lte,
}

fn compile_mime_operator(expected: &str) -> CacheOperator {
    let values = parse_list_values(expected)
        .into_iter()
        .filter_map(|value| compile_mime_matcher(&value))
        .collect::<Vec<_>>();
    if values.is_empty() {
        CacheOperator::NeverMatch
    } else {
        CacheOperator::MimeType(values)
    }
}

fn compile_mime_matcher(value: &str) -> Option<MimeMatcher> {
    let value = normalize_mime(value);
    if value.is_empty() {
        return None;
    }
    let (type_part, subtype) = value.split_once('/')?;
    if type_part.is_empty() || subtype.is_empty() {
        return None;
    }
    Some(MimeMatcher {
        type_part: type_part.to_string(),
        subtype_part: (subtype != "*").then(|| subtype.to_string()),
    })
}

fn compile_version_range(expected: &str) -> CacheOperator {
    let (min, max) = parse_pair(expected).unwrap_or((expected.trim(), ""));
    let min = (!min.trim().is_empty()).then(|| min.trim().to_string());
    let max = (!max.trim().is_empty()).then(|| max.trim().to_string());
    if min.is_none() && max.is_none() {
        return CacheOperator::NeverMatch;
    }
    if min
        .as_deref()
        .is_some_and(|value| parse_version_parts(value).is_none())
        || max
            .as_deref()
            .is_some_and(|value| parse_version_parts(value).is_none())
    {
        return CacheOperator::NeverMatch;
    }
    CacheOperator::VersionRange(min, max)
}

fn compile_number_compare(expected: &str, compare: NumberCompare) -> CacheOperator {
    let Some(expected) = parse_finite_f64(expected) else {
        return CacheOperator::NeverMatch;
    };
    let operator = match compare {
        NumberCompare::Gt => NumberOperator::Gt(expected),
        NumberCompare::Gte => NumberOperator::Gte(expected),
        NumberCompare::Lt => NumberOperator::Lt(expected),
        NumberCompare::Lte => NumberOperator::Lte(expected),
    };
    CacheOperator::Number(operator)
}

fn compile_mod_operator(divisor: &str, expected: &str) -> CacheOperator {
    let Some(divisor) = parse_u64(divisor).filter(|value| *value > 0) else {
        return CacheOperator::NeverMatch;
    };
    let Some(remainder) = parse_u64(expected).filter(|value| *value < divisor) else {
        return CacheOperator::NeverMatch;
    };
    CacheOperator::Number(NumberOperator::Mod { divisor, remainder })
}

fn compile_dynamic_mod_operator(expected: &str) -> CacheOperator {
    let Some((divisor, remainder)) = parse_pair(expected) else {
        return CacheOperator::NeverMatch;
    };
    let Some(divisor) = parse_u64(divisor).filter(|value| *value > 0) else {
        return CacheOperator::NeverMatch;
    };
    let Some(remainder) = parse_u64(remainder).filter(|value| *value < divisor) else {
        return CacheOperator::NeverMatch;
    };
    CacheOperator::Number(NumberOperator::Mod { divisor, remainder })
}

fn compile_ip_operator(expected: &str, compare: IpCompare) -> CacheOperator {
    let Ok(expected) = expected.trim().parse::<IpAddr>() else {
        return CacheOperator::NeverMatch;
    };
    let operator = match compare {
        IpCompare::Eq => IpOperator::Eq(expected),
        IpCompare::Gt => IpOperator::Gt(expected),
        IpCompare::Gte => IpOperator::Gte(expected),
        IpCompare::Lt => IpOperator::Lt(expected),
        IpCompare::Lte => IpOperator::Lte(expected),
    };
    CacheOperator::Ip(operator)
}

fn compile_ip_range_operator(expected: &str) -> CacheOperator {
    let Some((start, end)) = parse_pair(expected) else {
        return CacheOperator::NeverMatch;
    };
    let (Ok(start), Ok(end)) = (start.trim().parse::<IpAddr>(), end.trim().parse::<IpAddr>())
    else {
        return CacheOperator::NeverMatch;
    };
    if ip_to_u128(start).is_none() || ip_to_u128(end).is_none() {
        return CacheOperator::NeverMatch;
    }
    CacheOperator::Ip(IpOperator::Range(start, end))
}

fn compile_ip_mod_operator(divisor: &str, expected: &str) -> CacheOperator {
    let Some(divisor) = parse_u128(divisor).filter(|value| *value > 0) else {
        return CacheOperator::NeverMatch;
    };
    let Some(remainder) = parse_u128(expected).filter(|value| *value < divisor) else {
        return CacheOperator::NeverMatch;
    };
    CacheOperator::Ip(IpOperator::Mod { divisor, remainder })
}

fn compile_dynamic_ip_mod_operator(expected: &str) -> CacheOperator {
    let Some((divisor, remainder)) = parse_pair(expected) else {
        return CacheOperator::NeverMatch;
    };
    let Some(divisor) = parse_u128(divisor).filter(|value| *value > 0) else {
        return CacheOperator::NeverMatch;
    };
    let Some(remainder) = parse_u128(remainder).filter(|value| *value < divisor) else {
        return CacheOperator::NeverMatch;
    };
    CacheOperator::Ip(IpOperator::Mod { divisor, remainder })
}

fn compile_size_capacity(value: Option<&serde_json::Value>) -> Option<i64> {
    value
        .map(SizeCapacity::from_json)
        .map(|size| size.to_bytes())
        .filter(|bytes| *bytes > 0)
}

fn parse_extension_values(value: &str) -> Vec<String> {
    parse_list_values(value)
        .iter()
        .filter_map(|item| {
            let item = item.trim().trim_matches('"').to_ascii_lowercase();
            if item.is_empty() {
                None
            } else if item.starts_with('.') {
                Some(item)
            } else {
                Some(format!(".{item}"))
            }
        })
        .collect()
}

fn value_in_list(value: &str, values: &[String], case_insensitive: bool) -> bool {
    if values.is_empty() {
        return false;
    }
    if case_insensitive {
        values.iter().any(|item| eq_case_insensitive(value, item))
    } else {
        values.iter().any(|item| item == value)
    }
}

fn mime_matches(value: &str, matchers: &[MimeMatcher]) -> bool {
    let value = normalize_mime(value);
    let Some((type_part, subtype)) = value.split_once('/') else {
        return false;
    };
    matchers.iter().any(|matcher| {
        matcher.type_part == type_part
            && matcher
                .subtype_part
                .as_ref()
                .map(|expected| expected == subtype)
                .unwrap_or(true)
    })
}

fn number_matches(value: &str, operator: &NumberOperator) -> bool {
    match operator {
        NumberOperator::EqInt(expected) => value
            .trim()
            .parse::<i64>()
            .is_ok_and(|actual| actual == *expected),
        NumberOperator::EqFloat(expected) => {
            parse_finite_f64(value).is_some_and(|actual| actual == *expected)
        }
        NumberOperator::Gt(expected) => {
            parse_finite_f64(value).is_some_and(|actual| actual > *expected)
        }
        NumberOperator::Gte(expected) => {
            parse_finite_f64(value).is_some_and(|actual| actual >= *expected)
        }
        NumberOperator::Lt(expected) => {
            parse_finite_f64(value).is_some_and(|actual| actual < *expected)
        }
        NumberOperator::Lte(expected) => {
            parse_finite_f64(value).is_some_and(|actual| actual <= *expected)
        }
        NumberOperator::Mod { divisor, remainder } => value
            .trim()
            .parse::<u64>()
            .is_ok_and(|actual| actual % *divisor == *remainder),
    }
}

fn version_range_matches(value: &str, min: Option<&str>, max: Option<&str>) -> bool {
    let value = value.trim();
    if value.is_empty() {
        return false;
    }
    if let Some(min) = min
        && compare_versions(value, min) == Some(std::cmp::Ordering::Less)
    {
        return false;
    }
    if let Some(max) = max
        && compare_versions(value, max) == Some(std::cmp::Ordering::Greater)
    {
        return false;
    }
    min.is_some() || max.is_some()
}

fn ip_matches(value: &str, operator: &IpOperator) -> bool {
    let Ok(actual) = value.trim().parse::<IpAddr>() else {
        return false;
    };
    match operator {
        IpOperator::Eq(expected) => actual == *expected,
        IpOperator::Gt(expected) => {
            compare_ip(actual, *expected).is_some_and(|ordering| ordering.is_gt())
        }
        IpOperator::Gte(expected) => {
            compare_ip(actual, *expected).is_some_and(|ordering| ordering.is_ge())
        }
        IpOperator::Lt(expected) => {
            compare_ip(actual, *expected).is_some_and(|ordering| ordering.is_lt())
        }
        IpOperator::Lte(expected) => {
            compare_ip(actual, *expected).is_some_and(|ordering| ordering.is_le())
        }
        IpOperator::Range(start, end) => {
            let (Some(actual), Some(start), Some(end)) =
                (ip_to_u128(actual), ip_to_u128(*start), ip_to_u128(*end))
            else {
                return false;
            };
            let (start, end) = if start <= end {
                (start, end)
            } else {
                (end, start)
            };
            actual >= start && actual <= end
        }
        IpOperator::Mod { divisor, remainder } => {
            ip_to_u128(actual).is_some_and(|actual| actual % *divisor == *remainder)
        }
    }
}

fn normalize_mime(value: &str) -> String {
    value
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

fn parse_pair(value: &str) -> Option<(&str, &str)> {
    value.split_once(',').or_else(|| value.split_once('-'))
}

fn parse_finite_f64(value: &str) -> Option<f64> {
    value
        .trim()
        .parse::<f64>()
        .ok()
        .filter(|value| value.is_finite())
}

fn parse_u64(value: &str) -> Option<u64> {
    value.trim().parse::<u64>().ok()
}

fn parse_u128(value: &str) -> Option<u128> {
    value.trim().parse::<u128>().ok()
}

fn compare_ip(left: IpAddr, right: IpAddr) -> Option<std::cmp::Ordering> {
    Some(ip_to_u128(left)?.cmp(&ip_to_u128(right)?))
}

fn ip_to_u128(ip: IpAddr) -> Option<u128> {
    match ip {
        IpAddr::V4(value) => Some(u32::from(value) as u128),
        IpAddr::V6(value) => Some(u128::from(value)),
    }
}

fn compare_versions(left: &str, right: &str) -> Option<std::cmp::Ordering> {
    let left = parse_version_parts(left)?;
    let right = parse_version_parts(right)?;
    let len = left.len().max(right.len());
    for index in 0..len {
        let left = *left.get(index).unwrap_or(&0);
        let right = *right.get(index).unwrap_or(&0);
        match left.cmp(&right) {
            std::cmp::Ordering::Equal => {}
            ordering => return Some(ordering),
        }
    }
    Some(std::cmp::Ordering::Equal)
}

fn parse_version_parts(value: &str) -> Option<Vec<u64>> {
    let parts = value
        .trim()
        .split('.')
        .map(|part| part.parse::<u64>().ok())
        .collect::<Option<Vec<_>>>()?;
    (!parts.is_empty()).then_some(parts)
}

fn eq_value(value: &str, expected: &str, case_insensitive: bool) -> bool {
    if case_insensitive {
        eq_case_insensitive(value, expected)
    } else {
        value == expected
    }
}

fn starts_with_value(value: &str, expected: &str, case_insensitive: bool) -> bool {
    if case_insensitive {
        starts_with_ascii_case_insensitive(value, expected)
    } else {
        value.starts_with(expected)
    }
}

fn ends_with_value(value: &str, expected: &str, case_insensitive: bool) -> bool {
    if case_insensitive {
        ends_with_ascii_case_insensitive(value, expected)
    } else {
        value.ends_with(expected)
    }
}

fn contains_value(value: &str, expected: &str, case_insensitive: bool) -> bool {
    if case_insensitive {
        contains_ascii_case_insensitive(value, expected)
    } else {
        value.contains(expected)
    }
}

fn eq_case_insensitive(value: &str, expected: &str) -> bool {
    if value.is_ascii() && expected.is_ascii() {
        value.eq_ignore_ascii_case(expected)
    } else {
        value.to_lowercase() == expected.to_lowercase()
    }
}

fn starts_with_ascii_case_insensitive(value: &str, prefix: &str) -> bool {
    if value.is_ascii() && prefix.is_ascii() {
        return value.len() >= prefix.len()
            && value.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes());
    }
    value.to_lowercase().starts_with(&prefix.to_lowercase())
}

fn ends_with_ascii_case_insensitive(value: &str, suffix: &str) -> bool {
    if value.is_ascii() && suffix.is_ascii() {
        return value.len() >= suffix.len()
            && value.as_bytes()[value.len() - suffix.len()..]
                .eq_ignore_ascii_case(suffix.as_bytes());
    }
    value.to_lowercase().ends_with(&suffix.to_lowercase())
}

fn contains_ascii_case_insensitive(value: &str, needle: &str) -> bool {
    if value.is_ascii() && needle.is_ascii() {
        return !needle.is_empty()
            && value.len() >= needle.len()
            && value
                .as_bytes()
                .windows(needle.len())
                .any(|part| part.eq_ignore_ascii_case(needle.as_bytes()));
    }
    value.to_lowercase().contains(&needle.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(operator: &str, expected: &str, actual: &str) -> bool {
        matches_case(operator, expected, actual, false)
    }

    fn matches_case(operator: &str, expected: &str, actual: &str, case_insensitive: bool) -> bool {
        match CacheOperator::compile(operator, expected, case_insensitive) {
            CacheOperator::Regex(re) => re.as_ref().is_some_and(|re| re.is_match(actual)),
            CacheOperator::NotRegex(re) => re.as_ref().is_some_and(|re| !re.is_match(actual)),
            CacheOperator::Wildcard(re) => re.as_ref().is_some_and(|re| re.is_match(actual)),
            CacheOperator::NotWildcard(re) => re.as_ref().is_some_and(|re| !re.is_match(actual)),
            CacheOperator::Eq(expected, ci) => eq_value(actual, &expected, ci),
            CacheOperator::Neq(expected, ci) => !eq_value(actual, &expected, ci),
            CacheOperator::Prefix(expected, ci) => starts_with_value(actual, &expected, ci),
            CacheOperator::Suffix(expected, ci) => ends_with_value(actual, &expected, ci),
            CacheOperator::Contains(expected, ci) => contains_value(actual, &expected, ci),
            CacheOperator::NotContains(expected, ci) => {
                !expected.is_empty() && !contains_value(actual, &expected, ci)
            }
            CacheOperator::In(values, ci) => value_in_list(actual, &values, ci),
            CacheOperator::NotIn(values, ci) => {
                !values.is_empty() && !value_in_list(actual, &values, ci)
            }
            CacheOperator::FileExt(values) => values.iter().any(|value| value == actual),
            CacheOperator::MimeType(matchers) => mime_matches(actual, &matchers),
            CacheOperator::Number(operator) => number_matches(actual, &operator),
            CacheOperator::VersionRange(min, max) => {
                version_range_matches(actual, min.as_deref(), max.as_deref())
            }
            CacheOperator::Ip(operator) => ip_matches(actual, &operator),
            CacheOperator::NeverMatch => false,
        }
    }

    #[test]
    fn cache_operator_supports_frontend_string_and_list_variants() {
        assert!(matches("regexp", "^[a-z]+\\d+$", "abc123"));
        assert!(matches("not regexp", "^admin", "guest"));
        assert!(matches("wildcard match", "/assets/*.js", "/assets/app.js"));
        assert!(matches(
            "wildcard not match",
            "/assets/*.js",
            "/assets/app.css"
        ));
        assert!(matches("eq", "admin", "admin"));
        assert!(matches("not", "admin", "guest"));
        assert!(!matches("not", "admin", "admin"));
        assert!(matches("prefix", "/api", "/api/users"));
        assert!(matches("suffix", ".jpg", "/a/b/c.jpg"));
        assert!(matches("contains", "public", "/static/public/app.js"));
        assert!(matches("not contains", "private", "/public/file"));
        assert!(!matches("not contains", "private", "/private/file"));
        assert!(matches("fileExt", ".ts", ".ts"));
        assert!(matches("fileExt", "ts", ".ts"));
        assert!(matches("fileExtension", r#"[".m3u8","ts"]"#, ".ts"));
        assert!(!matches("fileExt", ".ts", ".js"));
        assert!(matches("in", r#"["a","b"]"#, "a"));
        assert!(matches("not in", r#"["a","b"]"#, "c"));
        assert!(!matches("not in", r#"["a","b"]"#, "a"));
        assert!(matches_case("eq", "ADMIN", "admin", true));
        assert!(matches_case("contains", "PRIVATE", "/private/file", true));
    }

    #[test]
    fn cache_operator_supports_mime_version_number_mod_and_ip() {
        assert!(matches(
            "mime type",
            r#"["text/*","application/json"]"#,
            "text/html; charset=utf-8"
        ));
        assert!(matches(
            "mime type",
            "application/json,text/plain",
            "text/plain; charset=utf-8"
        ));
        assert!(matches(
            "mime type",
            "application/json",
            "application/json; charset=utf-8"
        ));
        assert!(!matches("mime type", "image/*", "text/html"));
        assert!(matches("version range", "1.2.0,2.0.0", "1.5.1"));
        assert!(!matches("version range", "1.2.0,2.0.0", "2.1.0"));
        assert!(matches("eq int", "42", "42"));
        assert!(matches("eq float", "1.5", "1.5"));
        assert!(matches("gt", "10", "11"));
        assert!(matches("gte", "10", "10"));
        assert!(matches("lt", "10", "9"));
        assert!(matches("lte", "10", "10"));
        assert!(matches("mod 10", "3", "23"));
        assert!(matches("mod 100", "23", "123"));
        assert!(matches("mod", "7,2", "23"));
        assert!(matches("eq ip", "192.0.2.1", "192.0.2.1"));
        assert!(matches("gt ip", "192.0.2.1", "192.0.2.2"));
        assert!(matches("gte ip", "192.0.2.1", "192.0.2.1"));
        assert!(matches("lt ip", "192.0.2.2", "192.0.2.1"));
        assert!(matches("lte ip", "192.0.2.1", "192.0.2.1"));
        assert!(matches("ip range", "192.0.2.1,192.0.2.10", "192.0.2.5"));
        assert!(matches("ip mod 10", "1", "0.0.0.11"));
        assert!(matches("ip mod 100", "11", "0.0.0.111"));
        assert!(matches("ip mod", "7,2", "0.0.0.23"));
    }

    #[test]
    fn invalid_negative_and_numeric_configs_do_not_match() {
        assert!(!matches("not regexp", "[", "anything"));
        assert!(!matches("not in", "[]", "anything"));
        assert!(!matches("eq int", "nan", "1"));
        assert!(!matches("eq float", "NaN", "1"));
        assert!(!matches("mod", "0,0", "1"));
        assert!(!matches("version range", "bad,2.0.0", "1.5.0"));
        assert!(!matches("mime type", "bad-mime", "text/html"));
        assert!(!matches("ip range", "bad,192.0.2.1", "192.0.2.1"));
        assert!(!matches("ip mod", "0,0", "192.0.2.1"));
    }

    #[test]
    fn cache_condition_compile_preserves_request_and_response_phase_metadata() {
        let request_cond = HTTPRequestCond {
            is_request: true,
            param: "${requestPath}".to_string(),
            operator: "eq".to_string(),
            value: "/index.html".to_string(),
            is_reverse: false,
            is_case_insensitive: false,
        };
        let response_cond = HTTPRequestCond {
            is_request: false,
            param: "${response.contentType}".to_string(),
            operator: "mime type".to_string(),
            value: "text/html".to_string(),
            is_reverse: false,
            is_case_insensitive: false,
        };

        let request_cond = CompiledCacheCond::compile(&request_cond);
        let response_cond = CompiledCacheCond::compile(&response_cond);

        assert!(request_cond.is_request);
        assert!(!request_cond.variable.is_response_known());
        assert!(!response_cond.is_request);
        assert!(response_cond.variable.is_response_known());
    }

    #[test]
    fn cache_variable_classifies_response_variables() {
        assert!(CacheVariable::compile("${response.contentType}").is_response_known());
        assert!(CacheVariable::compile("${response.header.Content-Type}").is_response_known());
        assert!(CacheVariable::compile("${responseHeader.Content-Type}").is_response_known());
        assert!(CacheVariable::compile("${status}").is_response_known());
        assert!(!CacheVariable::compile("${requestPath}").is_response_known());
        assert!(
            matches!(CacheVariable::compile("${arg.token}"), CacheVariable::Arg(value) if value == "token")
        );
        assert!(
            matches!(CacheVariable::compile("${header.User-Agent}"), CacheVariable::Header(value) if value == "User-Agent")
        );
        assert!(
            matches!(CacheVariable::compile("${cookie.sid}"), CacheVariable::Cookie(value) if value == "sid")
        );
    }
}
