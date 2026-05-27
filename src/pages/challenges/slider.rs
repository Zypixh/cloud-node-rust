use crate::pages::Lang;
use rand::Rng;

// ── Public API ───────────────────────────────────────────────────

/// Generate a puzzle-slider page using a deterministic target derived
/// from the WAF token's `slider_target()` anchor.
pub fn issue_html(
    lang: Lang,
    waf_token: &str,
    verify_route: &str,
    return_path: &str,
    target_anchor: u32,
) -> String {
    let tx = (target_anchor % 260) as f64;
    let ty = (target_anchor.wrapping_mul(17) % 160) as f64;
    issue_html_with_target(lang, waf_token, verify_route, return_path, tx, ty)
}

/// Low-level variant — accept explicit target coordinates.
pub fn issue_html_with_target(
    lang: Lang,
    waf_token: &str,
    verify_route: &str,
    return_path: &str,
    target_x: f64,
    target_y: f64,
) -> String {
    let sfx = random_js_id();
    let mut rng = rand::thread_rng();

    let off_x = (target_x + rng.r#gen_range(80.0f64..180.0)).clamp(0.0f64, 280.0);
    let off_y = (target_y + rng.r#gen_range(-40.0f64..40.0)).clamp(0.0f64, 160.0);
    let polygon = generate_puzzle_polygon(&mut rng);

    let (prompt, _ok, _fail) = match lang {
        Lang::ZhCn => ("拖动拼图块到缺口位置", "验证成功", "位置未对准，请重试"),
        Lang::En => (
            "Drag the puzzle piece to the gap",
            "Verified",
            "Misaligned, try again",
        ),
    };
    let rp_js = serde_json::to_string(return_path).unwrap_or_else(|_| "\"/\"".to_string());
    let route_js = serde_json::to_string(verify_route).unwrap_or_else(|_| "\"/\"".to_string());

    format!(
        r#"<div class="pzl" id="pzl_{sfx}">
<div class="pzl-bg" style="position:relative;width:320px;height:200px;margin:0 auto 14px;border-radius:12px;overflow:hidden">
<canvas id="bg_{sfx}" width="320" height="200" style="display:block;width:320px;height:200px"></canvas>
<div id="hl_{sfx}" class="pzl-hole" style="position:absolute;left:{tx:.0}px;top:{ty:.0}px;width:40px;height:40px;clip-path:{poly};background:rgba(0,0,0,.12);box-shadow:inset 0 0 0 2px rgba(0,0,0,.35),0 0 12px rgba(0,0,0,.25);pointer-events:none;border-radius:2px"></div>
<div id="pc_{sfx}" class="pzl-piece" style="position:absolute;left:{ox:.0}px;top:{oy:.0}px;width:40px;height:40px;clip-path:{poly};background:linear-gradient(135deg,rgba(99,102,241,.65),rgba(56,189,248,.65));cursor:grab;border-radius:2px;z-index:2"></div>
</div>
<p class="status" id="st_{sfx}">{prompt}</p>
<script>
(function(){{
var sf="{sfx}";var d=!1,sx=0,sy=0,px={ox:.0},py={oy:.0},tr=[],t0=Date.now();
var pc=document.getElementById('pc_'+sf),bg=document.getElementById('bg_'+sf),st=document.getElementById('st_'+sf);
function dr(){{
var c=bg.getContext('2d'),w=320,h=200;
var g=c.createLinearGradient(0,0,w,h);
g.addColorStop(0,'#6366f1');g.addColorStop(.5,'#38bdf8');g.addColorStop(1,'#22c55e');
c.fillStyle=g;c.fillRect(0,0,w,h);
c.strokeStyle='rgba(255,255,255,.06)';c.lineWidth=.5;
for(var x=0;x<w;x+=7){{c.beginPath();c.moveTo(x,0);c.lineTo(x,h);c.stroke()}}
for(var y=0;y<h;y+=7){{c.beginPath();c.moveTo(0,y);c.lineTo(w,y);c.stroke()}}
for(var i=0;i<24;i++){{c.fillStyle='rgba(255,255,255,'+(.04+Math.random()*.06)+')';c.beginPath();c.arc(Math.random()*w,Math.random()*h,3+Math.random()*14,0,Math.PI*2);c.fill()}}
c.strokeStyle='rgba(255,255,255,.04)';c.lineWidth=.5;
for(var i=0;i<w+h;i+=14){{c.beginPath();c.moveTo(i,0);c.lineTo(i-h,h);c.stroke()}}
for(var i=0;i<45;i++){{c.fillStyle='rgba(255,255,255,'+(.05+Math.random()*.08)+')';c.fillRect(Math.random()*w,Math.random()*h,1+Math.random()*3,1+Math.random()*3)}}
for(var i=0;i<5;i++){{c.strokeStyle='rgba(255,255,255,'+(.06+Math.random()*.06)+')';c.lineWidth=1.5+Math.random()*2;c.beginPath();c.arc(Math.random()*w,Math.random()*h,10+Math.random()*30,0,Math.PI*2);c.stroke()}}
}}
function ds(e){{d=!0;var p=e.touches?e.touches[0]:e;sx=p.clientX;sy=p.clientY;px=parseFloat(pc.style.left)||px;py=parseFloat(pc.style.top)||py;pc.style.cursor='grabbing'}}
function dm(e){{if(!d)return;e.preventDefault();var p=e.touches?e.touches[0]:e,nx=Math.max(0,Math.min(280,px+p.clientX-sx)),ny=Math.max(0,Math.min(160,py+p.clientY-sy));pc.style.left=nx+'px';pc.style.top=ny+'px'}}
(function cp(){{if(d){{var l=parseFloat(pc.style.left)||px,t=parseFloat(pc.style.top)||py;tr.push(Math.round(l)+','+Math.round(t))}}setTimeout(cp,20+40*Math.random())}})();
function de(e){{
if(!d)return;d=!1;pc.style.cursor='grab';
var el=Date.now()-t0,l=parseFloat(pc.style.left)||px,t=parseFloat(pc.style.top)||py;
	var q='__waf_token={wtok}&__waf_challenge_type=slider&x='+l.toFixed(1)+'&y='+t.toFixed(1)+'&__waf_elapsed='+el+'&__waf_trace='+encodeURIComponent(tr.join(';'))+'&__waf_return='+encodeURIComponent({rp_js});
	location.href={route_js}+'?'+q;
	}}
dr();
pc.addEventListener('mousedown',ds);document.addEventListener('mousemove',dm);document.addEventListener('mouseup',de);
pc.addEventListener('touchstart',ds,{{passive:!0}});document.addEventListener('touchmove',dm,{{passive:!1}});document.addEventListener('touchend',de);
}})();
</script>
</div>"#,
        sfx = sfx,
        tx = target_x,
        ty = target_y,
        ox = off_x,
        oy = off_y,
        poly = polygon,
        prompt = prompt,
        wtok = waf_token,
        rp_js = rp_js,
        route_js = route_js,
    )
}

// ── Verification (wired into maybe_serve_waf_verify) ─────────────

const TOLERANCE: f64 = 6.0;
const MIN_ELAPSED_MS: u64 = 1200;

/// Re-derive the target from the verifier's `slider_target()` anchor.
pub fn verify_anchor(
    target_anchor: u32,
    user_x: f64,
    user_y: f64,
    elapsed_ms: u64,
    trace: &str,
) -> bool {
    let tx = (target_anchor % 260) as f64;
    let ty = (target_anchor.wrapping_mul(17) % 160) as f64;
    (user_x - tx).abs() <= TOLERANCE
        && (user_y - ty).abs() <= TOLERANCE
        && elapsed_ms >= MIN_ELAPSED_MS
        && verify_trace(trace)
}

/// Verify with explicit target from encrypted token (standalone / test).
pub fn verify_explicit(
    token: &str,
    user_x: f64,
    user_y: f64,
    elapsed_ms: u64,
    trace: &str,
    secret: &[u8],
) -> bool {
    let payload = match crate::pages::challenges::decode_challenge_token(token, secret) {
        Some(p) => p,
        None => return false,
    };
    if crate::pages::challenges::is_token_expired(&payload) {
        return false;
    }
    let p = match payload.get("p").and_then(|v| v.as_object()) {
        Some(p) => p,
        None => return false,
    };
    let (tx, ty) = match (
        p.get("tx").and_then(|v| v.as_f64()),
        p.get("ty").and_then(|v| v.as_f64()),
    ) {
        (Some(x), Some(y)) => (x, y),
        _ => return false,
    };
    (user_x - tx).abs() <= TOLERANCE
        && (user_y - ty).abs() <= TOLERANCE
        && elapsed_ms >= MIN_ELAPSED_MS
        && verify_trace(trace)
}

// ── Helpers ──────────────────────────────────────────────────────

fn random_js_id() -> String {
    use rand::Rng;
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    (0..8)
        .map(|_| CHARS[rng.r#gen_range(0..CHARS.len())] as char)
        .collect()
}

fn generate_puzzle_polygon(rng: &mut impl Rng) -> String {
    let mut pts = Vec::with_capacity(24);
    for i in 0..24 {
        let a = 2.0 * std::f64::consts::PI * i as f64 / 24.0;
        let base_r = 42.0;
        let var = rng.r#gen_range(-10.0f64..12.0f64);
        let r = (base_r + var).clamp(8.0f64, 50.0f64);
        let x = (50.0f64 + r * a.cos()).clamp(2.0f64, 98.0f64);
        let y = (50.0f64 + r * a.sin()).clamp(2.0f64, 98.0f64);
        pts.push(format!("{:.1}% {:.1}%", x, y));
    }
    format!("polygon({})", pts.join(","))
}

fn verify_trace(trace: &str) -> bool {
    let points: Vec<(f64, f64)> = trace
        .split(';')
        .filter_map(|s| {
            let mut parts = s.split(',');
            let x = parts.next()?.parse().ok()?;
            let y = parts.next()?.parse().ok()?;
            Some((x, y))
        })
        .collect();
    if points.len() < 5 {
        return false;
    }
    let (x1, y1) = points[0];
    let (x2, y2) = points[points.len() - 1];
    let dx = x2 - x1;
    let dy = y2 - y1;
    let line_len = (dx * dx + dy * dy).sqrt();
    if line_len < 10.0 {
        return false;
    }
    let max_dev = points
        .iter()
        .map(|(x, y)| {
            let cross = ((x - x1) * dy - (y - y1) * dx).abs();
            cross / line_len
        })
        .fold(0.0f64, f64::max);
    max_dev > 2.0
}
