use base64::{Engine as _, engine::general_purpose};
use chrono::{DateTime, Utc};
use hmac::{Hmac, KeyInit, Mac};
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha1::Sha1;
use sha2::{Digest, Sha256};

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug)]
pub struct OssBackend {
    pub provider: OssProvider,
    pub endpoint_host: String,
    pub connect_addr: String,
    pub use_tls: bool,
    pub host_header: String,
    pub bucket: String,
    pub bucket_source: BucketSource,
    pub bucket_query_name: String,
    pub prefix: String,
    pub path_style: bool,
    pub access_key_id: String,
    pub access_key_secret: String,
    pub region: String,
    pub public_access: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OssProvider {
    AliyunOss,
    TencentCos,
    HuaweiObs,
    BaiduBos,
    QiniuKodo,
    AmazonS3,
    BackblazeB2,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BucketSource {
    Fixed,
    PathPrefix,
    QueryParam,
    Subdomain,
}

#[derive(Clone, Debug)]
pub struct OssRequestTransform {
    pub path_and_query: String,
    pub host_header: String,
    pub bucket: String,
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
struct LooseOssConfig {
    #[serde(default, alias = "type", alias = "ossType", alias = "providerCode")]
    r#type: String,
    #[serde(default, alias = "bucketName")]
    bucket: String,
    #[serde(default, alias = "endpointURL", alias = "url")]
    endpoint: String,
    #[serde(default, alias = "domain", alias = "host")]
    host: String,
    #[serde(default, alias = "accessKeyId", alias = "accessID", alias = "secretId")]
    access_key_id: String,
    #[serde(
        default,
        alias = "accessKeySecret",
        alias = "secretKey",
        alias = "accessSecret"
    )]
    access_key_secret: String,
    #[serde(default)]
    region: String,
    #[serde(default, alias = "dir", alias = "directory", alias = "root")]
    prefix: String,
    #[serde(default, alias = "forcePathStyle")]
    path_style: Option<bool>,
    #[serde(
        default,
        alias = "bucketMode",
        alias = "bucketType",
        alias = "bucketAccessType",
        alias = "bucketParam"
    )]
    bucket_source: String,
    #[serde(
        default,
        alias = "bucketArgName",
        alias = "bucketParamName",
        alias = "bucketArg",
        alias = "bucketQuery"
    )]
    bucket_query_name: String,
    #[serde(default, alias = "accessDomain", alias = "visitDomain")]
    access_domain: String,
    #[serde(default, alias = "acl", alias = "accessControl")]
    access_control: String,
    #[serde(default)]
    options: Option<Value>,
}

impl BucketSource {
    fn from_hint(hint: &str) -> Self {
        let raw = hint.trim().to_ascii_lowercase();
        if raw.contains("前缀") || raw.contains("路径") {
            return Self::PathPrefix;
        }
        if raw.contains("参数") {
            return Self::QueryParam;
        }
        if raw.contains("子域") {
            return Self::Subdomain;
        }
        match raw.replace(['_', '-', ' '], "").as_str() {
            "1" | "fixed" | "specified" | "specify" | "bucketname" | "fixedbucket" | "指定"
            | "指定存储桶" => Self::Fixed,
            "2" | "path" | "pathprefix" | "urlpath" | "urlprefix" | "prefix" | "bucketinpath"
            | "pathbucket" | "url前缀" | "路径前缀" => Self::PathPrefix,
            "3" | "query" | "queryparam" | "param" | "arg" | "urlparam" | "urlarg"
            | "bucketinquery" | "querybucket" | "参数" | "url参数" => Self::QueryParam,
            "4" | "subdomain" | "domain" | "host" | "vhost" | "virtualhost"
            | "bucketinsubdomain" | "subdomainbucket" | "子域名" => Self::Subdomain,
            _ => Self::Fixed,
        }
    }
}

impl OssProvider {
    pub fn from_protocol_and_type(protocol: Option<&str>, type_hint: &str) -> Self {
        let from_type = Self::from_hint(type_hint);
        if from_type != Self::Unknown {
            return from_type;
        }
        let protocol_hint = protocol
            .and_then(|protocol| protocol.split_once(':').map(|(_, suffix)| suffix))
            .unwrap_or("");
        Self::from_hint(protocol_hint)
    }

    fn from_hint(hint: &str) -> Self {
        let normalized = hint
            .trim()
            .to_ascii_lowercase()
            .replace(['_', '-', ' '], "");
        match normalized.as_str() {
            "aliyun" | "ali" | "alioss" | "aliyunoss" | "oss" => Self::AliyunOss,
            "tencent" | "tencentcos" | "qcloudcos" | "cos" => Self::TencentCos,
            "huawei" | "huaweicloud" | "huaweiobs" | "obs" => Self::HuaweiObs,
            "baidu" | "baidubos" | "bos" => Self::BaiduBos,
            "qiniu" | "qiniukodo" | "kodo" => Self::QiniuKodo,
            "amazons3" | "amazon" | "aws" | "s3" => Self::AmazonS3,
            "backblazeb2" | "backblaze" | "b2" => Self::BackblazeB2,
            _ => Self::Unknown,
        }
    }

    fn service_name(self) -> &'static str {
        match self {
            Self::TencentCos => "cos",
            Self::HuaweiObs => "s3",
            Self::BaiduBos => "s3",
            Self::QiniuKodo => "s3",
            Self::AmazonS3 => "s3",
            Self::BackblazeB2 => "s3",
            Self::AliyunOss | Self::Unknown => "s3",
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Self::AliyunOss => "阿里云OSS",
            Self::TencentCos => "腾讯云COS",
            Self::HuaweiObs => "华为云OBS",
            Self::BaiduBos => "百度云BOS",
            Self::QiniuKodo => "七牛云Kodo",
            Self::AmazonS3 => "Amazon S3",
            Self::BackblazeB2 => "B2云存储",
            Self::Unknown => "对象存储",
        }
    }

    fn uses_aliyun_auth(self) -> bool {
        matches!(self, Self::AliyunOss)
    }
}

impl OssBackend {
    pub fn log_origin_address(&self) -> String {
        self.log_origin_address_for_bucket(&self.bucket)
    }

    pub fn log_origin_address_for_bucket(&self, bucket: &str) -> String {
        let bucket = bucket.trim();
        if bucket.is_empty() {
            self.provider.display_name().to_string()
        } else {
            format!("{} - {}", self.provider.display_name(), bucket)
        }
    }

    pub fn from_origin(origin: &crate::config_models::OriginConfig) -> anyhow::Result<Self> {
        let protocol = origin.addr.as_ref().and_then(|addr| match addr {
            crate::config_models::FlexibleAddr::Object(obj) => obj.protocol.as_deref(),
            crate::config_models::FlexibleAddr::String(raw) => Some(raw.as_str()),
        });
        let oss_value = origin.oss.clone().unwrap_or(Value::Null);
        let mut loose = parse_loose_config(&oss_value)?;
        merge_options(&mut loose);

        let provider = OssProvider::from_protocol_and_type(protocol, &loose.r#type);
        let bucket_source = BucketSource::from_hint(&first_non_empty(&[
            loose.bucket_source.clone(),
            find_string(
                &oss_value,
                &[
                    "bucketSource",
                    "bucketMode",
                    "bucketType",
                    "bucketAccessType",
                    "bucketNameType",
                    "bucketPosition",
                    "bucketFrom",
                    "bucketParam",
                ],
            ),
        ]));
        let bucket_query_name = first_non_empty(&[
            loose.bucket_query_name.clone(),
            find_string(
                &oss_value,
                &[
                    "bucketArgName",
                    "bucketQueryName",
                    "bucketParamName",
                    "argName",
                    "paramName",
                    "bucketArg",
                    "bucketQuery",
                ],
            ),
            "bucket".to_string(),
        ]);
        let bucket = first_non_empty(&[
            loose.bucket.clone(),
            find_string(&oss_value, &["bucket", "bucketName", "Bucket", "name"]),
        ]);
        let region = first_non_empty(&[
            loose.region.clone(),
            find_string(&oss_value, &["region", "Region"]),
        ]);
        let endpoint_raw = with_endpoint_protocol(
            &first_non_empty(&[
                loose.access_domain.clone(),
                loose.endpoint.clone(),
                loose.host.clone(),
                origin.request_host.clone(),
                find_string(
                    &oss_value,
                    &[
                        "accessDomain",
                        "visitDomain",
                        "endpoint",
                        "endpointURL",
                        "url",
                        "host",
                        "domain",
                        "addr",
                    ],
                ),
                default_endpoint(provider, &region),
            ]),
            loose.options.as_ref(),
        );
        let access_key_id = first_non_empty(&[
            loose.access_key_id.clone(),
            find_string(
                &oss_value,
                &[
                    "accessKeyId",
                    "accessKeyID",
                    "accessID",
                    "accessKey",
                    "secretId",
                    "SecretId",
                ],
            ),
        ]);
        let access_key_secret = first_non_empty(&[
            loose.access_key_secret.clone(),
            find_string(
                &oss_value,
                &["accessKeySecret", "secretKey", "accessSecret", "SecretKey"],
            ),
        ]);
        let prefix = normalize_prefix(&first_non_empty(&[
            loose.prefix.clone(),
            find_string(
                &oss_value,
                &["prefix", "dir", "directory", "root", "basePath"],
            ),
        ]));
        let public_access = matches!(
            first_non_empty(&[
                loose.access_control.clone(),
                find_string(
                    &oss_value,
                    &["accessControl", "acl", "permission", "visibility"]
                ),
            ])
            .to_ascii_lowercase()
            .as_str(),
            "public" | "publicread" | "公开" | "1" | "true"
        );

        if endpoint_raw.is_empty() {
            anyhow::bail!("OSS origin {} missing endpoint/host", origin.id);
        }
        if bucket.is_empty() && bucket_source == BucketSource::Fixed {
            anyhow::bail!("OSS origin {} missing bucket", origin.id);
        }

        let parsed = parse_endpoint(&endpoint_raw);
        let path_style = loose
            .path_style
            .unwrap_or_else(|| find_path_style(&oss_value).unwrap_or(false));
        let host_header = match bucket_source {
            BucketSource::Fixed if !path_style => virtual_host(&bucket, &parsed.host),
            _ => parsed.host.clone(),
        };
        let port = parsed.port.unwrap_or(if parsed.use_tls { 443 } else { 80 });
        let connect_addr = format_host_port(&parsed.host, port);
        let public_access = public_access || access_key_id.is_empty();

        Ok(Self {
            provider,
            endpoint_host: parsed.host,
            connect_addr,
            use_tls: parsed.use_tls,
            host_header,
            bucket,
            bucket_source,
            bucket_query_name,
            prefix,
            path_style,
            access_key_id,
            access_key_secret,
            region,
            public_access,
        })
    }

    pub fn transform_request(
        &self,
        method: &Method,
        path: &str,
        query: Option<&str>,
        headers: &HeaderMap,
        now: DateTime<Utc>,
    ) -> OssRequestTransform {
        let Some(mut resolved) = self.resolve_request(path, query, headers) else {
            return OssRequestTransform {
                path_and_query: path_and_query(path, query),
                host_header: self.host_header.clone(),
                bucket: self.bucket.clone(),
                headers: vec![("host".to_string(), self.host_header.clone())],
            };
        };
        let canonical_uri = resolved.canonical_uri.clone();
        let mut signed_headers = vec![("host".to_string(), resolved.host_header.clone())];
        let content_type = header_value(headers, "content-type").unwrap_or_default();
        let content_md5 = header_value(headers, "content-md5").unwrap_or_default();

        if self.public_access || self.access_key_id.is_empty() || self.access_key_secret.is_empty()
        {
            return OssRequestTransform {
                path_and_query: resolved.path_and_query(),
                host_header: resolved.host_header,
                bucket: resolved.bucket,
                headers: signed_headers,
            };
        }

        if self.provider.uses_aliyun_auth() {
            let date = now.to_rfc2822().replace("+0000", "GMT");
            signed_headers.push(("date".to_string(), date.clone()));
            let oss_headers = canonicalized_oss_headers(headers);
            for (name, value) in &oss_headers {
                signed_headers.push((name.clone(), value.clone()));
            }
            let canonical_resource = format!(
                "/{}{}{}",
                resolved.bucket,
                if resolved.object_key.is_empty() {
                    ""
                } else {
                    "/"
                },
                resolved.object_key
            ) + &query_suffix_from_str(&resolved.query);
            let string_to_sign = format!(
                "{}\n{}\n{}\n{}\n{}{}",
                method.as_str(),
                content_md5,
                content_type,
                date,
                format_canonicalized_oss_headers(&oss_headers),
                canonical_resource
            );
            let signature =
                hmac_sha1_base64(self.access_key_secret.as_bytes(), string_to_sign.as_bytes());
            signed_headers.push((
                "authorization".to_string(),
                format!("OSS {}:{}", self.access_key_id, signature),
            ));
        } else {
            let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
            let short_date = now.format("%Y%m%d").to_string();
            let region = if self.region.is_empty() {
                infer_region(&self.endpoint_host, self.provider)
            } else {
                self.region.clone()
            };
            signed_headers.push(("x-amz-date".to_string(), amz_date.clone()));
            signed_headers.push((
                "x-amz-content-sha256".to_string(),
                "UNSIGNED-PAYLOAD".into(),
            ));

            let canonical_query = canonicalize_query(&resolved.query);
            resolved.query = canonical_query.clone();
            let canonical_headers = format!(
                "host:{}\nx-amz-content-sha256:UNSIGNED-PAYLOAD\nx-amz-date:{}\n",
                resolved.host_header, amz_date
            );
            let signed_header_names = "host;x-amz-content-sha256;x-amz-date";
            let canonical_request = format!(
                "{}\n{}\n{}\n{}\n{}\n{}",
                method.as_str(),
                canonical_uri,
                canonical_query,
                canonical_headers,
                signed_header_names,
                "UNSIGNED-PAYLOAD"
            );
            let credential_scope = format!(
                "{}/{}/{}/aws4_request",
                short_date,
                region,
                self.provider.service_name()
            );
            let string_to_sign = format!(
                "AWS4-HMAC-SHA256\n{}\n{}\n{}",
                amz_date,
                credential_scope,
                hex::encode(Sha256::digest(canonical_request.as_bytes()))
            );
            let signing_key = aws_v4_signing_key(
                self.access_key_secret.as_bytes(),
                &short_date,
                &region,
                self.provider.service_name(),
            );
            let signature = hex::encode(hmac_sha256_bytes(&signing_key, string_to_sign.as_bytes()));
            signed_headers.push((
                "authorization".to_string(),
                format!(
                    "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
                    self.access_key_id, credential_scope, signed_header_names, signature
                ),
            ));
        }

        OssRequestTransform {
            path_and_query: resolved.path_and_query(),
            host_header: resolved.host_header,
            bucket: resolved.bucket,
            headers: signed_headers,
        }
    }

    fn resolve_request(
        &self,
        path: &str,
        query: Option<&str>,
        headers: &HeaderMap,
    ) -> Option<ResolvedOssRequest> {
        let original_query = query.unwrap_or("");
        let downstream_host = header_value(headers, "host").unwrap_or_default();
        let mut bucket = self.bucket.clone();
        let mut clean_path = path.trim_start_matches('/').to_string();
        let mut query_pairs = parse_query_pairs(original_query);
        let mut host_header = self.host_header.clone();

        match self.bucket_source {
            BucketSource::Fixed => {}
            BucketSource::PathPrefix => {
                let (first, rest) = split_first_path_segment(&clean_path)?;
                bucket = first;
                clean_path = rest;
            }
            BucketSource::QueryParam => {
                bucket = take_query_param(&mut query_pairs, &self.bucket_query_name)?;
            }
            BucketSource::Subdomain => {
                bucket = extract_subdomain_bucket(&downstream_host)?;
            }
        }
        if bucket.is_empty() {
            return None;
        }

        let object_key = join_key(&self.prefix, &clean_path);
        let canonical_uri = if self.path_style || self.bucket_source == BucketSource::PathPrefix {
            format!(
                "/{}{}{}",
                pct_path_segment(&bucket),
                if object_key.is_empty() { "" } else { "/" },
                pct_path(&object_key)
            )
        } else {
            if matches!(
                self.bucket_source,
                BucketSource::Fixed | BucketSource::Subdomain
            ) {
                host_header = virtual_host(&bucket, &self.endpoint_host);
            }
            format!("/{}", pct_path(&object_key))
        };

        Some(ResolvedOssRequest {
            bucket,
            object_key,
            canonical_uri,
            query: serialize_query_pairs(&query_pairs),
            host_header,
        })
    }
}

#[derive(Clone, Debug)]
struct ResolvedOssRequest {
    bucket: String,
    object_key: String,
    canonical_uri: String,
    query: String,
    host_header: String,
}

impl ResolvedOssRequest {
    fn path_and_query(&self) -> String {
        if self.query.is_empty() {
            self.canonical_uri.clone()
        } else {
            format!("{}?{}", self.canonical_uri, self.query)
        }
    }
}

#[derive(Clone, Debug)]
struct ParsedEndpoint {
    host: String,
    port: Option<u16>,
    use_tls: bool,
}

fn parse_loose_config(value: &Value) -> anyhow::Result<LooseOssConfig> {
    if value.is_null() {
        return Ok(LooseOssConfig::default());
    }
    if let Some(s) = value.as_str() {
        return serde_json::from_str::<LooseOssConfig>(s).or_else(|_| {
            Ok(LooseOssConfig {
                endpoint: s.to_string(),
                ..Default::default()
            })
        });
    }
    serde_json::from_value(value.clone()).map_err(Into::into)
}

fn merge_options(config: &mut LooseOssConfig) {
    let Some(options) = config.options.clone() else {
        return;
    };
    if config.bucket.is_empty() {
        config.bucket = find_string(&options, &["bucket", "bucketName"]);
    }
    if config.endpoint.is_empty() {
        config.endpoint = find_string(
            &options,
            &[
                "endpoint",
                "endpointURL",
                "url",
                "host",
                "domain",
                "accessDomain",
                "visitDomain",
            ],
        );
    }
    if config.access_key_id.is_empty() {
        config.access_key_id = find_string(
            &options,
            &[
                "accessKeyId",
                "accessKeyID",
                "accessID",
                "accessKey",
                "secretId",
            ],
        );
    }
    if config.access_key_secret.is_empty() {
        config.access_key_secret =
            find_string(&options, &["accessKeySecret", "secretKey", "accessSecret"]);
    }
    if config.region.is_empty() {
        config.region = find_string(&options, &["region"]);
    }
    if config.prefix.is_empty() {
        config.prefix = find_string(&options, &["prefix", "dir", "directory", "root"]);
    }
    if config.path_style.is_none() {
        config.path_style = find_path_style(&options);
    }
    if config.bucket_source.is_empty() {
        config.bucket_source = find_string(
            &options,
            &[
                "bucketSource",
                "bucketMode",
                "bucketType",
                "bucketAccessType",
                "bucketNameType",
                "bucketPosition",
                "bucketFrom",
                "bucketParam",
            ],
        );
    }
    if config.bucket_query_name.is_empty() {
        config.bucket_query_name = find_string(
            &options,
            &[
                "bucketArgName",
                "bucketQueryName",
                "bucketParamName",
                "argName",
                "paramName",
                "bucketArg",
                "bucketQuery",
            ],
        );
    }
    if config.access_domain.is_empty() {
        config.access_domain = find_string(&options, &["accessDomain", "visitDomain"]);
    }
    if config.access_control.is_empty() {
        config.access_control = find_string(
            &options,
            &[
                "accessControl",
                "acl",
                "permission",
                "visibility",
                "isPublic",
                "public",
            ],
        );
    }
}

fn default_endpoint(provider: OssProvider, region: &str) -> String {
    let region = region.trim();
    match provider {
        OssProvider::TencentCos if !region.is_empty() => format!("cos.{}.myqcloud.com", region),
        _ => String::new(),
    }
}

fn with_endpoint_protocol(endpoint: &str, options: Option<&Value>) -> String {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() || endpoint.contains("://") {
        return endpoint.to_string();
    }
    let protocol = options
        .map(|options| find_string(options, &["protocol", "scheme"]))
        .unwrap_or_default();
    let protocol = protocol
        .trim()
        .trim_end_matches("://")
        .trim_end_matches(':');
    if protocol.eq_ignore_ascii_case("http") || protocol.eq_ignore_ascii_case("https") {
        format!("{}://{}", protocol.to_ascii_lowercase(), endpoint)
    } else {
        endpoint.to_string()
    }
}

fn parse_endpoint(raw: &str) -> ParsedEndpoint {
    let trimmed = raw.trim().trim_end_matches('/');
    let with_scheme = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("https://{}", trimmed)
    };
    if let Ok(uri) = with_scheme.parse::<http::Uri>() {
        let scheme = uri.scheme_str().unwrap_or("https");
        return ParsedEndpoint {
            host: uri.host().unwrap_or(trimmed).to_string(),
            port: uri.port_u16(),
            use_tls: !scheme.eq_ignore_ascii_case("http"),
        };
    }
    ParsedEndpoint {
        host: trimmed
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .to_string(),
        port: None,
        use_tls: true,
    }
}

fn virtual_host(bucket: &str, endpoint_host: &str) -> String {
    if endpoint_host.starts_with(&format!("{}.", bucket)) {
        endpoint_host.to_string()
    } else {
        format!("{}.{}", bucket, endpoint_host)
    }
}

fn format_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

fn normalize_prefix(prefix: &str) -> String {
    prefix.trim_matches('/').to_string()
}

fn first_non_empty(values: &[String]) -> String {
    values
        .iter()
        .map(|value| value.trim())
        .find(|value| !value.is_empty())
        .unwrap_or("")
        .to_string()
}

fn find_string(value: &Value, keys: &[&str]) -> String {
    let Some(obj) = value.as_object() else {
        return String::new();
    };
    for key in keys {
        if let Some(v) = obj.get(*key) {
            if let Some(s) = v.as_str() {
                if !s.trim().is_empty() {
                    return s.trim().to_string();
                }
            } else if v.is_number() || v.is_boolean() {
                return v.to_string();
            }
        }
    }
    String::new()
}

fn find_path_style(value: &Value) -> Option<bool> {
    let obj = value.as_object()?;
    for key in [
        "pathStyle",
        "forcePathStyle",
        "bucketAccessStyle",
        "bucketStyle",
        "endpointBucketStyle",
        "endpointBucketAccessStyle",
        "bucketEndpointStyle",
        "endpointStyle",
        "accessStyle",
    ] {
        if let Some(v) = obj.get(key) {
            if let Some(parsed) = parse_bool_like(v) {
                return Some(parsed);
            }
            if let Some(s) = v.as_str() {
                match s
                    .trim()
                    .to_ascii_lowercase()
                    .replace(['_', '-', ' '], "")
                    .as_str()
                {
                    "path" | "pathstyle" | "pathbucket" | "路径" | "路径样式" => {
                        return Some(true);
                    }
                    "subdomain" | "virtualhost" | "virtualhosted" | "vhost" | "domain" | "host"
                    | "子域名" | "子域名样式" => return Some(false),
                    _ => {}
                }
            }
        }
    }
    None
}

fn parse_bool_like(value: &Value) -> Option<bool> {
    if let Some(b) = value.as_bool() {
        return Some(b);
    }
    if let Some(n) = value.as_i64() {
        return Some(n != 0);
    }
    if let Some(s) = value.as_str() {
        match s.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => return Some(true),
            "0" | "false" | "no" | "off" => return Some(false),
            _ => {}
        }
    }
    None
}

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let name = HeaderName::from_bytes(name.as_bytes()).ok()?;
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string)
}

fn path_and_query(path: &str, query: Option<&str>) -> String {
    query
        .filter(|query| !query.is_empty())
        .map(|query| format!("{}?{}", path, query))
        .unwrap_or_else(|| path.to_string())
}

fn query_suffix_from_str(query: &str) -> String {
    if query.is_empty() {
        String::new()
    } else {
        format!("?{}", query)
    }
}

fn canonicalized_oss_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    let mut headers = headers
        .iter()
        .filter_map(|(name, value)| {
            let name = name.as_str().to_ascii_lowercase();
            if !name.starts_with("x-oss-") {
                return None;
            }
            value
                .to_str()
                .ok()
                .map(|value| (name, normalize_header_value(value)))
        })
        .collect::<Vec<_>>();
    headers.sort_by(|a, b| a.0.cmp(&b.0));
    headers
}

fn format_canonicalized_oss_headers(headers: &[(String, String)]) -> String {
    headers
        .iter()
        .map(|(name, value)| format!("{}:{}\n", name, value))
        .collect::<String>()
}

fn normalize_header_value(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn parse_query_pairs(query: &str) -> Vec<(String, Option<String>)> {
    if query.is_empty() {
        return Vec::new();
    }
    query
        .split('&')
        .filter(|part| !part.is_empty())
        .map(|part| {
            part.split_once('=')
                .map(|(key, value)| (key.to_string(), Some(value.to_string())))
                .unwrap_or_else(|| (part.to_string(), None))
        })
        .collect()
}

fn serialize_query_pairs(pairs: &[(String, Option<String>)]) -> String {
    pairs
        .iter()
        .map(|(key, value)| match value {
            Some(value) => format!("{}={}", key, value),
            None => key.clone(),
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn take_query_param(pairs: &mut Vec<(String, Option<String>)>, name: &str) -> Option<String> {
    let idx = pairs.iter().position(|(key, _)| key == name)?;
    let (_, value) = pairs.remove(idx);
    value.filter(|value| !value.is_empty())
}

fn split_first_path_segment(path: &str) -> Option<(String, String)> {
    let clean = path.trim_start_matches('/');
    if clean.is_empty() {
        return None;
    }
    let (first, rest) = clean.split_once('/').unwrap_or((clean, ""));
    if first.is_empty() {
        None
    } else {
        Some((first.to_string(), rest.to_string()))
    }
}

fn extract_subdomain_bucket(host: &str) -> Option<String> {
    let host = normalize_host_name(host);
    let mut labels = host.split('.');
    let bucket = labels.next()?;
    if bucket.is_empty() || labels.count() < 2 {
        None
    } else {
        Some(bucket.to_string())
    }
}

fn normalize_host_name(host: &str) -> String {
    let host = host.trim();
    let host = host
        .strip_prefix('[')
        .and_then(|rest| rest.split_once(']').map(|(host, _)| host))
        .unwrap_or_else(|| host.split(':').next().unwrap_or(host));
    host.trim_end_matches('.').to_ascii_lowercase()
}

fn join_key(prefix: &str, path: &str) -> String {
    match (prefix.is_empty(), path.is_empty()) {
        (true, true) => String::new(),
        (true, false) => path.to_string(),
        (false, true) => prefix.to_string(),
        (false, false) => format!("{}/{}", prefix, path.trim_start_matches('/')),
    }
}

fn pct_path(path: &str) -> String {
    path.split('/')
        .map(pct_path_segment)
        .collect::<Vec<_>>()
        .join("/")
}

fn pct_path_segment(segment: &str) -> String {
    pct_encode_bytes(&pct_decode_component(segment))
}

fn pct_query(value: &str) -> String {
    pct_encode_bytes(&pct_decode_component(value))
}

fn pct_decode_component(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut idx = 0;
    while idx < bytes.len() {
        if bytes[idx] == b'%'
            && idx + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_value(bytes[idx + 1]), hex_value(bytes[idx + 2]))
        {
            out.push((hi << 4) | lo);
            idx += 3;
        } else {
            out.push(bytes[idx]);
            idx += 1;
        }
    }
    out
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn pct_encode_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for byte in bytes {
        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            _ => out.push_str(&format!("%{:02X}", byte)),
        }
    }
    out
}

fn canonicalize_query(query: &str) -> String {
    if query.is_empty() {
        return String::new();
    }
    let mut pairs = query
        .split('&')
        .map(|part| {
            let (k, v) = part.split_once('=').unwrap_or((part, ""));
            (pct_query(k), pct_query(v))
        })
        .collect::<Vec<_>>();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("&")
}

fn infer_region(endpoint_host: &str, provider: OssProvider) -> String {
    let host = endpoint_host.to_ascii_lowercase();
    if provider == OssProvider::TencentCos
        && let Some(region) = host.split('.').find(|part| {
            part.starts_with("ap-") || part.starts_with("na-") || part.starts_with("eu-")
        })
    {
        return region.to_string();
    }
    if matches!(provider, OssProvider::AmazonS3 | OssProvider::QiniuKodo) {
        let parts = host.split('.').collect::<Vec<_>>();
        for idx in 0..parts.len().saturating_sub(1) {
            if parts[idx] == "s3" && idx + 1 < parts.len() && parts[idx + 1] != "amazonaws" {
                return parts[idx + 1].to_string();
            }
        }
        return "us-east-1".to_string();
    }
    "us-east-1".to_string()
}

fn hmac_sha1_base64(secret: &[u8], data: &[u8]) -> String {
    let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(data);
    general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

fn hmac_sha256_bytes(secret: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn aws_v4_signing_key(secret: &[u8], date: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac_sha256_bytes(
        format!("AWS4{}", String::from_utf8_lossy(secret)).as_bytes(),
        date.as_bytes(),
    );
    let k_region = hmac_sha256_bytes(&k_date, region.as_bytes());
    let k_service = hmac_sha256_bytes(&k_region, service.as_bytes());
    hmac_sha256_bytes(&k_service, b"aws4_request")
}

pub fn insert_headers(
    request: &mut pingora_http::RequestHeader,
    headers: Vec<(String, String)>,
) -> anyhow::Result<()> {
    for (name, value) in headers {
        let value = HeaderValue::from_str(&value)?;
        request.insert_header(name, value)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_models::{FlexibleAddr, OriginConfig, OriginTlsSecurityVerifyMode};
    use chrono::TimeZone;
    use serde_json::json;

    fn origin(provider: &str, oss: Value) -> OriginConfig {
        OriginConfig {
            id: 1,
            name: String::new(),
            addr: Some(FlexibleAddr::String(format!("oss:{}", provider))),
            is_on: true,
            weight: 1,
            health_check: None,
            request_host: String::new(),
            follow_host: false,
            follow_port: false,
            http2_enabled: false,
            http3_enabled: false,
            conn_timeout: None,
            read_timeout: None,
            idle_timeout: None,
            write_timeout: None,
            cert: None,
            tls_security_verify_mode: OriginTlsSecurityVerifyMode::Auto,
            tls_verify: None,
            oss: Some(oss),
        }
    }

    #[test]
    fn virtual_host_public_bucket_preserves_query() {
        let backend = OssBackend::from_origin(&origin(
            "s3",
            json!({
                "bucket": "assets",
                "endpoint": "https://s3.us-west-2.amazonaws.com",
                "prefix": "/static/"
            }),
        ))
        .unwrap();

        let transform = backend.transform_request(
            &Method::GET,
            "/img/logo.png",
            Some("v=1&cache=no"),
            &HeaderMap::new(),
            Utc.with_ymd_and_hms(2026, 5, 12, 1, 2, 3).unwrap(),
        );

        assert_eq!(backend.connect_addr, "s3.us-west-2.amazonaws.com:443");
        assert_eq!(transform.host_header, "assets.s3.us-west-2.amazonaws.com");
        assert_eq!(
            transform.path_and_query,
            "/static/img/logo.png?v=1&cache=no"
        );
        assert_eq!(
            transform.headers,
            vec![("host".to_string(), transform.host_header)]
        );
    }

    #[test]
    fn path_style_s3_auth_signs_unsigned_payload() {
        let backend = OssBackend::from_origin(&origin(
            "s3",
            json!({
                "bucket": "assets",
                "endpoint": "http://127.0.0.1:9000",
                "pathStyle": true,
                "accessKeyId": "test-ak",
                "accessKeySecret": "test-sk",
                "region": "us-east-1"
            }),
        ))
        .unwrap();

        let transform = backend.transform_request(
            &Method::GET,
            "/index.html",
            None,
            &HeaderMap::new(),
            Utc.with_ymd_and_hms(2026, 5, 12, 1, 2, 3).unwrap(),
        );
        let authorization = transform
            .headers
            .iter()
            .find(|(name, _)| name == "authorization")
            .map(|(_, value)| value.as_str())
            .unwrap();

        assert_eq!(backend.connect_addr, "127.0.0.1:9000");
        assert_eq!(backend.host_header, "127.0.0.1");
        assert_eq!(transform.path_and_query, "/assets/index.html");
        assert!(
            authorization.starts_with(
                "AWS4-HMAC-SHA256 Credential=test-ak/20260512/us-east-1/s3/aws4_request"
            )
        );
        assert!(
            transform
                .headers
                .iter()
                .any(|(name, value)| name == "x-amz-content-sha256" && value == "UNSIGNED-PAYLOAD")
        );
    }

    #[test]
    fn endpoint_bucket_style_text_controls_path_style() {
        let path_backend = OssBackend::from_origin(&origin(
            "s3",
            json!({
                "bucket": "assets",
                "endpoint": "https://s3.us-west-2.amazonaws.com",
                "options": {
                    "endpointBucketStyle": "path"
                }
            }),
        ))
        .unwrap();
        let path_transform = path_backend.transform_request(
            &Method::GET,
            "/index.html",
            None,
            &HeaderMap::new(),
            Utc.with_ymd_and_hms(2026, 5, 12, 1, 2, 3).unwrap(),
        );
        assert_eq!(path_backend.host_header, "s3.us-west-2.amazonaws.com");
        assert_eq!(path_transform.path_and_query, "/assets/index.html");

        let subdomain_backend = OssBackend::from_origin(&origin(
            "s3",
            json!({
                "bucket": "assets",
                "endpoint": "https://s3.us-west-2.amazonaws.com",
                "endpointBucketStyle": "subdomain"
            }),
        ))
        .unwrap();
        let subdomain_transform = subdomain_backend.transform_request(
            &Method::GET,
            "/index.html",
            None,
            &HeaderMap::new(),
            Utc.with_ymd_and_hms(2026, 5, 12, 1, 2, 3).unwrap(),
        );
        assert_eq!(
            subdomain_backend.host_header,
            "assets.s3.us-west-2.amazonaws.com"
        );
        assert_eq!(subdomain_transform.path_and_query, "/index.html");
    }

    #[test]
    fn encoded_path_and_query_are_not_double_encoded() {
        let backend = OssBackend::from_origin(&origin(
            "s3",
            json!({
                "bucket": "assets",
                "endpoint": "https://s3.us-west-2.amazonaws.com"
            }),
        ))
        .unwrap();

        let transform = backend.transform_request(
            &Method::GET,
            "/dir/%E4%B8%AD%E6%96%87 file.png",
            Some("q=%E4%B8%AD%E6%96%87&space=a b"),
            &HeaderMap::new(),
            Utc.with_ymd_and_hms(2026, 5, 12, 1, 2, 3).unwrap(),
        );

        assert_eq!(
            transform.path_and_query,
            "/dir/%E4%B8%AD%E6%96%87%20file.png?q=%E4%B8%AD%E6%96%87&space=a b"
        );
        assert_eq!(
            canonicalize_query("q=%E4%B8%AD%E6%96%87&space=a b"),
            "q=%E4%B8%AD%E6%96%87&space=a%20b"
        );
    }

    #[test]
    fn signed_s3_query_is_sent_canonicalized() {
        let backend = OssBackend::from_origin(&origin(
            "s3",
            json!({
                "bucket": "assets",
                "endpoint": "https://s3.us-west-2.amazonaws.com",
                "accessKeyId": "test-ak",
                "accessKeySecret": "test-sk",
                "region": "us-west-2"
            }),
        ))
        .unwrap();

        let transform = backend.transform_request(
            &Method::GET,
            "/image.png",
            Some("space=a b&z=last&a=first"),
            &HeaderMap::new(),
            Utc.with_ymd_and_hms(2026, 5, 12, 1, 2, 3).unwrap(),
        );

        assert_eq!(
            transform.path_and_query,
            "/image.png?a=first&space=a%20b&z=last"
        );
    }

    #[test]
    fn subdomain_bucket_requires_bucket_label() {
        assert_eq!(
            extract_subdomain_bucket("bucket.example.com"),
            Some("bucket".to_string())
        );
        assert_eq!(extract_subdomain_bucket("example.com"), None);
    }

    #[test]
    fn control_plane_bucket_param_selects_bucket_source() {
        let path_backend = OssBackend::from_origin(&origin(
            "tencentCOS",
            json!({
                "bucketParam": "2",
                "bucketArgName": "ARG",
                "options": {
                    "region": "ap-guangzhou",
                    "secretId": "test-ak",
                    "secretKey": "test-sk"
                }
            }),
        ))
        .unwrap();
        assert_eq!(path_backend.bucket_source, BucketSource::PathPrefix);
        assert_eq!(path_backend.bucket_query_name, "ARG");

        let query_backend = OssBackend::from_origin(&origin(
            "tencentCOS",
            json!({
                "bucketParam": "3",
                "bucketArgName": "ARG",
                "options": {
                    "region": "ap-guangzhou",
                    "secretId": "test-ak",
                    "secretKey": "test-sk"
                }
            }),
        ))
        .unwrap();
        assert_eq!(query_backend.bucket_source, BucketSource::QueryParam);
        assert_eq!(query_backend.bucket_query_name, "ARG");

        let subdomain_backend = OssBackend::from_origin(&origin(
            "tencentCOS",
            json!({
                "bucketParam": "4",
                "options": {
                    "region": "ap-guangzhou",
                    "secretId": "test-ak",
                    "secretKey": "test-sk"
                }
            }),
        ))
        .unwrap();
        assert_eq!(subdomain_backend.bucket_source, BucketSource::Subdomain);
    }

    #[test]
    fn tencent_cos_infers_endpoint_from_region() {
        let backend = OssBackend::from_origin(&origin(
            "tencentCOS",
            json!({
                "bucketName": "tencent-1",
                "options": {
                    "region": "ap-guangzhou",
                    "secretId": "test-ak",
                    "secretKey": "test-sk"
                }
            }),
        ))
        .unwrap();

        assert_eq!(backend.endpoint_host, "cos.ap-guangzhou.myqcloud.com");
        assert_eq!(
            backend.host_header,
            "tencent-1.cos.ap-guangzhou.myqcloud.com"
        );
        assert_eq!(backend.connect_addr, "cos.ap-guangzhou.myqcloud.com:443");
    }

    #[test]
    fn qiniu_bucket_uses_s3_authorization() {
        let backend = OssBackend::from_origin(&origin(
            "qiniu",
            json!({
                "bucket": "test1-moyu",
                "options": {
                    "domain": "s3.cn-east-1.qiniucs.com",
                    "protocol": "https",
                    "accessKey": "test-ak",
                    "secretKey": "test-sk",
                    "isPublic": false
                }
            }),
        ))
        .unwrap();

        let transform = backend.transform_request(
            &Method::GET,
            "/video.mp4",
            Some("v=1"),
            &HeaderMap::new(),
            Utc.with_ymd_and_hms(2026, 5, 12, 1, 2, 3).unwrap(),
        );
        let authorization = transform
            .headers
            .iter()
            .find(|(name, _)| name == "authorization")
            .map(|(_, value)| value.as_str())
            .unwrap();

        assert_eq!(transform.host_header, "test1-moyu.s3.cn-east-1.qiniucs.com");
        assert_eq!(transform.path_and_query, "/video.mp4?v=1");
        assert!(
            authorization.starts_with(
                "AWS4-HMAC-SHA256 Credential=test-ak/20260512/cn-east-1/s3/aws4_request"
            )
        );
        assert!(
            transform
                .headers
                .iter()
                .any(|(name, _)| name == "x-amz-date")
        );
    }

    #[test]
    fn aliyun_oss_uses_oss_authorization() {
        let backend = OssBackend::from_origin(&origin(
            "aliyun",
            json!({
                "bucketName": "assets",
                "endpoint": "oss-cn-hangzhou.aliyuncs.com",
                "accessKeyId": "test-ak",
                "accessKeySecret": "test-sk"
            }),
        ))
        .unwrap();

        let transform = backend.transform_request(
            &Method::GET,
            "/index.html",
            Some("uploads"),
            &HeaderMap::new(),
            Utc.with_ymd_and_hms(2026, 5, 12, 1, 2, 3).unwrap(),
        );
        let authorization = transform
            .headers
            .iter()
            .find(|(name, _)| name == "authorization")
            .map(|(_, value)| value.as_str())
            .unwrap();

        assert_eq!(transform.host_header, "assets.oss-cn-hangzhou.aliyuncs.com");
        assert_eq!(transform.path_and_query, "/index.html?uploads");
        assert!(authorization.starts_with("OSS test-ak:"));
        assert!(transform.headers.iter().any(|(name, _)| name == "date"));
    }

    #[test]
    fn aliyun_x_oss_query_params_are_preserved() {
        let backend = OssBackend::from_origin(&origin(
            "aliyun",
            json!({
                "bucketName": "assets",
                "endpoint": "oss-cn-hangzhou.aliyuncs.com",
                "accessKeyId": "test-ak",
                "accessKeySecret": "test-sk"
            }),
        ))
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert("x-oss-meta-name", HeaderValue::from_static("demo"));
        let transform = backend.transform_request(
            &Method::GET,
            "/image.png",
            Some("x-oss-process=image/resize,p_50&v=1"),
            &headers,
            Utc.with_ymd_and_hms(2026, 5, 12, 1, 2, 3).unwrap(),
        );

        assert_eq!(
            transform.path_and_query,
            "/image.png?x-oss-process=image/resize,p_50&v=1"
        );
        assert!(
            transform
                .headers
                .iter()
                .any(|(name, value)| name == "authorization" && value.starts_with("OSS test-ak:"))
        );
        assert!(
            transform
                .headers
                .iter()
                .any(|(name, value)| name == "x-oss-meta-name" && value == "demo")
        );
    }
}
