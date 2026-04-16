use base64::{Engine as _, engine::general_purpose};
use lazy_static::lazy_static;
use md5_legacy;
use regex::Regex;
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::Sha256;
use urlencoding::{decode, encode};

lazy_static! {
    static ref RE_VARIABLE: Regex = Regex::new(r"\$\{([^{}]+)\}").unwrap();
}

/// 处理变量修饰符管道
fn apply_modifiers(mut value: String, modifiers: &[&str]) -> String {
    for &modifier in modifiers {
        value = match modifier.trim() {
            "urlEncode" => encode(&value).into_owned(),
            "urlDecode" => decode(&value).map(|c| c.into_owned()).unwrap_or(value),
            "base64Encode" => general_purpose::STANDARD.encode(&value),
            "base64Decode" => {
                String::from_utf8(general_purpose::STANDARD.decode(&value).unwrap_or_default())
                    .unwrap_or_default()
            }
            "md5" => format!("{:x}", md5_legacy::compute(value.as_bytes())),
            "sha1" => {
                let mut hasher = Sha1::new();
                hasher.update(value.as_bytes());
                hex::encode(hasher.finalize())
            }
            "sha256" => {
                let mut hasher = Sha256::new();
                hasher.update(value.as_bytes());
                hex::encode(hasher.finalize())
            }
            "toLowerCase" => value.to_lowercase(),
            "toUpperCase" => value.to_uppercase(),
            _ => value,
        };
    }
    value
}

/// 泛型变量解析函数，接受一个解析器闭包
pub fn format_template<F>(template: &str, resolver: F) -> String
where
    F: Fn(&str) -> String,
{
    RE_VARIABLE
        .replace_all(template, |caps: &regex::Captures| {
            let full_var = &caps[1];
            let parts: Vec<&str> = full_var.split('|').collect();
            let var_name = parts[0].trim();
            let modifiers = &parts[1..];

            let mut value = resolver(var_name);
            if !modifiers.is_empty() {
                value = apply_modifiers(value, modifiers);
            }
            value
        })
        .into_owned()
}
