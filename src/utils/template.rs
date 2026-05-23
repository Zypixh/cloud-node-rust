use base64::{Engine as _, engine::general_purpose};
use md5_legacy;
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::Sha256;
use urlencoding::{decode, encode};

fn apply_modifier(value: String, modifier: &str) -> String {
    match modifier.trim() {
        "urlEncode" => encode(&value).into_owned(),
        "urlDecode" => decode(&value).map(|c| c.into_owned()).unwrap_or(value),
        "base64Encode" => general_purpose::STANDARD.encode(&value),
        "base64Decode" => String::from_utf8(
            general_purpose::STANDARD
                .decode(&value)
                .unwrap_or_default(),
        )
        .unwrap_or_default(),
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
    }
}

fn resolve_template_variable<F>(expression: &str, resolver: &F) -> String
where
    F: Fn(&str) -> String,
{
    let mut parts = expression.split('|');
    let name = parts.next().unwrap_or_default().trim();
    let mut value = resolver(name);
    for modifier in parts {
        value = apply_modifier(value, modifier);
    }
    value
}

/// 泛型变量解析函数，接受一个解析器闭包
pub fn format_template<F>(template: &str, resolver: F) -> String
where
    F: Fn(&str) -> String,
{
    let Some(mut search_start) = template.find("${") else {
        return template.to_string();
    };

    let mut result = String::with_capacity(template.len());
    let mut literal_start = 0;
    loop {
        result.push_str(&template[literal_start..search_start]);
        let expr_start = search_start + 2;
        let Some(end_offset) = template[expr_start..].find('}') else {
            result.push_str(&template[search_start..]);
            return result;
        };
        let expr_end = expr_start + end_offset;
        result.push_str(&resolve_template_variable(&template[expr_start..expr_end], &resolver));
        literal_start = expr_end + 1;
        let Some(next_offset) = template[literal_start..].find("${") else {
            result.push_str(&template[literal_start..]);
            return result;
        };
        search_start = literal_start + next_offset;
    }
}
