pub mod challenges;
pub mod lang;

pub use lang::Lang;

/// Top safety page wrapping `<html>` — UAM challenge family.
pub fn uam_challenge_page(
    body_html: &str,
    script: &str,
    lang: Lang,
    request_id: &str,
) -> String {
    let t = lang::text(lang);
    let css = shared_css();
    format!(
        r#"<!doctype html><html lang="{lang_attr}"><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>{title}</title><style>{css}</style></head><body>{lang_bar}<main class="card"><div class="mark waf"></div>{body_html}</main></body>{script}</html>"#,
        lang_attr = lang.html_attr(),
        title    = t.title,
        css      = css,
        lang_bar = lang_bar_html(lang, request_id),
        body_html = body_html,
        script   = script,
    )
}

/// WAF slider challenge full page.
pub fn waf_slider_page(
    lang: Lang,
    request_id: &str,
    slider_html: &str,
    script: &str,
) -> String {
    let t = lang::text(lang);
    let css = shared_css();
    format!(
        r#"<!doctype html><html lang="{lang_attr}"><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>{title}</title><style>{css}</style></head><body>{lang_bar}{slider_html}<noscript><p class="error">{nojs}</p></noscript></body>{script}</html>"#,
        lang_attr = lang.html_attr(),
        title    = t.title,
        css      = css,
        lang_bar = lang_bar_html(lang, request_id),
        slider_html = slider_html,
        nojs    = t.no_js,
        script  = script,
    )
}

/// WAF / CC block page.
pub fn block_page(
    lang: Lang,
    status: u16,
    reason: &str,
    request_id: &str,
    body_extra: &str,
) -> String {
    let t = lang::text(lang);
    let css = shared_css();
    let status_text = t.access_denied;
    format!(
        r#"<!doctype html><html lang="{lang_attr}"><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>{status} {status_text}</title><style>{css}</style></head><body>{lang_bar}<main class="card"><div class="mark block"></div><h1>{status} {status_text}</h1><p>{reason}</p>{body_extra}<div class="meta">{footer} &middot; Request {request_id}</div></main></body></html>"#,
        lang_attr = lang.html_attr(),
        css      = css,
        lang_bar = lang_bar_html(lang, request_id),
        status   = status,
        status_text = status_text,
        reason   = reason,
        body_extra = body_extra,
        footer   = t.footer,
        request_id = request_id,
    )
}

// ── internal helpers ──────────────────────────────────────────

pub(crate) fn lang_bar_html(lang: Lang, request_id: &str) -> String {
    let other = lang.other();
    format!(
        r#"<nav class="lang-bar"><span class="lang-req">#{request_id}</span><button class="lang-btn" onclick="var u=new URL(location);u.searchParams.set('lang','{other}');location=u.toString()" title="{title}">{label}</button></nav>"#,
        request_id = request_id,
        other   = other.query_str(),
        title   = match lang { Lang::ZhCn => "Switch to English", Lang::En => "切换到中文" },
        label   = match lang { Lang::ZhCn => "English", Lang::En => "中文" },
    )
}

pub(crate) fn shared_css() -> &'static str {
    r#":root{color-scheme:light dark;--bg:linear-gradient(135deg,#f6f8fb,#e8ecf1);--card-bg:rgba(255,255,255,.96);--card-border:rgba(15,23,42,.08);--text:#1f2937;--muted:#667085;--dim:#98a2b3;--green:#22c55e;--blue:#0ea5e9;--red:#dc2626;--waf:linear-gradient(135deg,#6366f1,#38bdf8);--block:linear-gradient(135deg,#ef4444,#f97316);--shadow:0 20px 60px rgba(15,23,42,.1);--lang-bg:rgba(15,23,42,.04)}@media(prefers-color-scheme:dark){:root{--bg:linear-gradient(135deg,#0f172a,#111827 55%,#1e293b);--card-bg:rgba(24,34,48,.94);--card-border:rgba(255,255,255,.1);--text:#f9fafb;--muted:#aeb8c7;--dim:#667085;--shadow:0 20px 60px rgba(0,0,0,.4);--lang-bg:rgba(255,255,255,.06)}}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI','Noto Sans SC',sans-serif;background:var(--bg);color:var(--text);-webkit-font-smoothing:antialiased}.lang-bar{position:fixed;top:14px;right:16px;display:flex;align-items:center;gap:10px;z-index:10}.lang-req{font-size:11px;color:var(--dim);font-family:ui-monospace,'SF Mono',monospace;background:var(--lang-bg);padding:4px 10px;border-radius:999px}.lang-btn{font-size:13px;font-weight:600;color:var(--text);background:var(--lang-bg);border:1px solid var(--card-border);padding:5px 14px;border-radius:999px;cursor:pointer;transition:all .15s}.lang-btn:hover{background:var(--text);color:#fff}.card{width:min(92vw,460px);padding:40px 34px;border-radius:20px;background:var(--card-bg);border:1px solid var(--card-border);box-shadow:var(--shadow);text-align:center}.mark{width:58px;height:58px;margin:0 auto 22px;border-radius:18px;box-shadow:0 14px 34px rgba(99,102,241,.3)}.mark.waf{background:var(--waf)}.mark.block{background:var(--block)}h1{margin:0 0 10px;font-size:23px;font-weight:700}p{margin:0 0 24px;color:var(--muted);line-height:1.65;font-size:15px}.progress,.track{height:46px;border-radius:999px;background:rgba(148,163,184,.18);overflow:hidden;position:relative}.progress span{display:block;width:42%;height:100%;border-radius:999px;background:linear-gradient(90deg,var(--green),var(--blue));animation:pulse 1.3s ease-in-out infinite}.track{touch-action:none;cursor:pointer;border:1px solid var(--card-border)}.track:before{content:'';position:absolute;inset:0;background:repeating-linear-gradient(110deg,transparent 0 13px,rgba(148,163,184,.12) 14px 16px);border-radius:999px}.fill{position:absolute;inset:0 auto 0 0;width:0;background:linear-gradient(90deg,var(--green),var(--blue));border-radius:999px}.handle{position:absolute;top:3px;left:3px;width:40px;height:40px;border-radius:50%;display:grid;place-items:center;background:#fff;color:#0f172a;font-weight:800;box-shadow:0 6px 20px rgba(0,0,0,.22);user-select:none}.status{margin-top:14px;font-size:14px;color:var(--muted)}.error{color:var(--red)}.meta{margin-top:18px;font-size:12px;color:var(--dim)}@keyframes pulse{0%,100%{transform:translateX(-18%)}50%{transform:translateX(150%)}}"#
}

/// Determine the preferred language from query param (`?lang=zh` / `?lang=en`)
/// or Accept-Language header, falling back to English.
pub fn detect_lang(
    query_lang: Option<&str>,
    accept_language: Option<&str>,
) -> Lang {
    if let Some(q) = query_lang {
        let q = q.trim().to_lowercase();
        if q.starts_with("zh") { return Lang::ZhCn; }
        if q.starts_with("en") { return Lang::En; }
    }
    if let Some(al) = accept_language {
        let al = al.to_lowercase();
        if al.contains("zh") { return Lang::ZhCn; }
    }
    Lang::En
}
