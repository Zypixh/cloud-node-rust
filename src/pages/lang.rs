#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    ZhCn,
    En,
}

impl Lang {
    pub fn html_attr(self) -> &'static str {
        match self {
            Lang::ZhCn => "zh-CN",
            Lang::En => "en",
        }
    }

    pub fn other(self) -> Lang {
        match self {
            Lang::ZhCn => Lang::En,
            Lang::En => Lang::ZhCn,
        }
    }

    pub fn query_str(self) -> &'static str {
        match self {
            Lang::ZhCn => "zh",
            Lang::En => "en",
        }
    }
}

pub struct Texts {
    pub title: &'static str,
    pub no_js: &'static str,
    pub access_denied: &'static str,
    pub footer: &'static str,

    // ── UAM challenge variants ──
    pub checking: &'static str,
    pub checking_sub: &'static str,
    pub computing_pow: &'static str,
    pub slide_prompt: &'static str,
    pub slide_status: &'static str,
    pub slide_retry: &'static str,
    pub verifying: &'static str,
    pub verify_failed: &'static str,

    // ── WAF challenge ──
    pub waf_title: &'static str,
    pub waf_subtitle: &'static str,
    pub waf_slide_status: &'static str,
}

pub fn text(lang: Lang) -> Texts {
    match lang {
        Lang::ZhCn => Texts {
            title: "安全验证",
            no_js: "此安全验证需要启用 JavaScript。",
            access_denied: "访问被拒绝",
            footer: "由 ${product.name} 安全防护提供",
            checking: "正在检查您的浏览器",
            checking_sub: "请稍候，我们正在验证您的浏览器能力。",
            computing_pow: "正在计算工作量证明 ({difficulty})",
            slide_prompt: "请完成滑块验证以继续。",
            slide_status: "将滑块拖拽到高亮区域",
            slide_retry: "位置未对准，请重试",
            verifying: "验证中...",
            verify_failed: "验证失败，请重试",
            waf_title: "安全检查",
            waf_subtitle: "请完成安全验证以继续访问。此操作有助于保护网站免受自动化攻击。",
            waf_slide_status: "将滑块拖拽到高亮区域",
        },
        Lang::En => Texts {
            title: "Security Verification",
            no_js: "JavaScript is required for this security check.",
            access_denied: "Access Denied",
            footer: "Protected by ${product.name} Security",
            checking: "Checking your browser",
            checking_sub: "Please wait while we verify your browser capability.",
            computing_pow: "Computing proof of work ({difficulty})",
            slide_prompt: "Slide to complete the browser check.",
            slide_status: "Slide the handle to the highlighted zone",
            slide_retry: "Not quite there, please try again",
            verifying: "Verifying...",
            verify_failed: "Verification failed, please retry",
            waf_title: "Security Check",
            waf_subtitle: "Please complete the security check to continue. This helps protect the site from automated abuse.",
            waf_slide_status: "Slide the handle to the highlighted zone",
        },
    }
}
