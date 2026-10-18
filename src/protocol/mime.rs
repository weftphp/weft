//! Media types for file extensions, for serving static files.

use std::path::Path;

/// Returned for unknown extensions: arbitrary binary data.
pub const DEFAULT: &str = "application/octet-stream";

/// The media type for an extension (without the dot, any case).
pub fn for_extension(ext: &str) -> Option<&'static str> {
    let ext = ext.to_ascii_lowercase();
    Some(match ext.as_str() {
        // text
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" | "cjs" => "text/javascript; charset=utf-8",
        "txt" | "text" | "log" => "text/plain; charset=utf-8",
        "csv" => "text/csv; charset=utf-8",
        "md" | "markdown" => "text/markdown; charset=utf-8",
        "xml" => "application/xml",
        "ics" => "text/calendar",
        "vtt" => "text/vtt",
        // structured data
        "json" | "map" => "application/json",
        "jsonld" => "application/ld+json",
        "webmanifest" => "application/manifest+json",
        "yaml" | "yml" => "application/yaml",
        "toml" => "application/toml",
        "wasm" => "application/wasm",
        "pdf" => "application/pdf",
        "rtf" => "application/rtf",
        "atom" => "application/atom+xml",
        "rss" => "application/rss+xml",
        "xhtml" => "application/xhtml+xml",
        // images
        "png" => "image/png",
        "jpg" | "jpeg" | "jpe" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "svg" | "svgz" => "image/svg+xml",
        "ico" => "image/vnd.microsoft.icon",
        "bmp" => "image/bmp",
        "tif" | "tiff" => "image/tiff",
        "heic" => "image/heic",
        // fonts
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        // audio
        "mp3" => "audio/mpeg",
        "ogg" | "oga" => "audio/ogg",
        "opus" => "audio/opus",
        "wav" => "audio/wav",
        "flac" => "audio/flac",
        "aac" => "audio/aac",
        "m4a" => "audio/mp4",
        "mid" | "midi" => "audio/midi",
        // video
        "mp4" | "m4v" => "video/mp4",
        "webm" => "video/webm",
        "ogv" => "video/ogg",
        "mov" => "video/quicktime",
        "avi" => "video/x-msvideo",
        "mpeg" | "mpg" => "video/mpeg",
        "m3u8" => "application/vnd.apple.mpegurl",
        "ts" => "video/mp2t",
        // archives and packages
        "zip" => "application/zip",
        "gz" | "tgz" => "application/gzip",
        "bz2" => "application/x-bzip2",
        "xz" => "application/x-xz",
        "zst" => "application/zstd",
        "tar" => "application/x-tar",
        "7z" => "application/x-7z-compressed",
        "rar" => "application/vnd.rar",
        "jar" => "application/java-archive",
        "apk" => "application/vnd.android.package-archive",
        "deb" => "application/vnd.debian.binary-package",
        // office documents
        "doc" => "application/msword",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls" => "application/vnd.ms-excel",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "ppt" => "application/vnd.ms-powerpoint",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "odt" => "application/vnd.oasis.opendocument.text",
        "ods" => "application/vnd.oasis.opendocument.spreadsheet",
        "epub" => "application/epub+zip",
        _ => return None,
    })
}

/// The media type for a path's extension, or [`DEFAULT`].
pub fn for_path(path: impl AsRef<Path>) -> &'static str {
    path.as_ref()
        .extension()
        .and_then(|e| e.to_str())
        .and_then(for_extension)
        .unwrap_or(DEFAULT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookups() {
        assert_eq!(for_path("/srv/www/index.HTML"), "text/html; charset=utf-8");
        assert_eq!(for_path("app.wasm"), "application/wasm");
        assert_eq!(for_path("archive.tar.gz"), "application/gzip");
        assert_eq!(for_path("no-extension"), DEFAULT);
        assert_eq!(for_path("weird.unknownext"), DEFAULT);
        assert_eq!(for_extension("PNG"), Some("image/png"));
    }
}
