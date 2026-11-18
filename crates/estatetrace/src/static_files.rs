use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use rust_embed::Embed;

#[derive(Embed)]
#[folder = "../../ui/dist"]
#[prefix = ""]
pub struct Assets;

pub async fn static_handler(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    if path.is_empty() || path == "index.html" {
        return serve("index.html");
    }
    if Assets::get(path).is_some() {
        return serve(path);
    }
    // SPA fallback
    serve("index.html")
}

fn serve(path: &str) -> Response {
    match Assets::get(path) {
        Some(file) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, mime.as_ref())],
                file.data.to_vec(),
            )
                .into_response()
        }
        None => {
            // Dev fallback placeholder when UI not built yet.
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                PLACEHOLDER_HTML.as_bytes().to_vec(),
            )
                .into_response()
        }
    }
}

const PLACEHOLDER_HTML: &str = r#"<!doctype html>
<html><head><meta charset="utf-8"/><title>EstateTrace</title>
<style>
:root{--et-header:#1f2933;--et-sidebar:#243b53;--et-canvas:#f5f7fa;--et-accent:#0b6e4f}
body{margin:0;font-family:Segoe UI,system-ui,sans-serif;background:var(--et-canvas);color:#102a43}
header{background:var(--et-header);color:#fff;padding:1rem 1.5rem;font-size:1.25rem}
main{padding:1.5rem}
.card{background:#fff;border:1px solid #d9e2ec;padding:1rem;margin-bottom:1rem}
button{background:var(--et-accent);color:#fff;border:0;padding:.5rem 1rem;cursor:pointer}
code{background:#e4e7eb;padding:.1rem .3rem}
</style></head>
<body>
<header>EstateTrace</header>
<main>
<div class="card"><strong>UI bundle not built.</strong> Run <code>npm install && npm run build</code> in <code>ui/</code>, then rebuild the binary. API is available under <code>/api</code>.</div>
<div class="card"><a href="/api/health">/api/health</a></div>
</main>
</body></html>"#;