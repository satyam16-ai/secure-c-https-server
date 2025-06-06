#include "../include/https_server.h"
#include <strings.h>

// MIME type mapping structure
typedef struct
{
    const char *extension;
    const char *mime_type;
} mime_mapping_t;

// Common MIME type mappings
static const mime_mapping_t mime_types[] = {
    // Text
    {".html", "text/html; charset=utf-8"},
    {".htm", "text/html; charset=utf-8"},
    {".css", "text/css; charset=utf-8"},
    {".js", "application/javascript; charset=utf-8"},
    {".txt", "text/plain; charset=utf-8"},
    {".md", "text/markdown; charset=utf-8"},
    {".json", "application/json; charset=utf-8"},
    {".xml", "application/xml; charset=utf-8"},
    {".csv", "text/csv; charset=utf-8"},

    // Images
    {".jpg", "image/jpeg"},
    {".jpeg", "image/jpeg"},
    {".png", "image/png"},
    {".gif", "image/gif"},
    {".svg", "image/svg+xml"},
    {".ico", "image/x-icon"},
    {".webp", "image/webp"},

    // Fonts
    {".woff", "font/woff"},
    {".woff2", "font/woff2"},
    {".ttf", "font/ttf"},
    {".otf", "font/otf"},
    {".eot", "application/vnd.ms-fontobject"},

    // Documents
    {".pdf", "application/pdf"},
    {".doc", "application/msword"},
    {".docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    {".xls", "application/vnd.ms-excel"},
    {".xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    {".ppt", "application/vnd.ms-powerpoint"},
    {".pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"},

    // Archives
    {".zip", "application/zip"},
    {".tar", "application/x-tar"},
    {".gz", "application/gzip"},
    {".rar", "application/x-rar-compressed"},
    {".7z", "application/x-7z-compressed"},

    // Audio
    {".mp3", "audio/mpeg"},
    {".wav", "audio/wav"},
    {".ogg", "audio/ogg"},
    {".m4a", "audio/mp4"},
    {".flac", "audio/flac"},

    // Video
    {".mp4", "video/mp4"},
    {".webm", "video/webm"},
    {".avi", "video/x-msvideo"},
    {".mov", "video/quicktime"},
    {".mkv", "video/x-matroska"},

    // Other
    {".wasm", "application/wasm"},
    {".webmanifest", "application/manifest+json"},
    {".map", "application/json"},      // Source maps
    {NULL, "application/octet-stream"} // Default
};

// Initialize MIME types
void mime_init(void)
{
    // Nothing to initialize for now
}

// Get MIME type for file
const char *mime_get_type(const char *path)
{
    const char *ext;
    const mime_mapping_t *mapping;

    // Get file extension
    ext = get_file_extension(path);
    if (ext == NULL)
    {
        return mime_types[sizeof(mime_types) / sizeof(mime_types[0]) - 1].mime_type;
    }

    // Find matching MIME type
    for (mapping = mime_types; mapping->extension != NULL; mapping++)
    {
        if (strcasecmp(mapping->extension, ext) == 0)
        {
            return mapping->mime_type;
        }
    }

    // Return default MIME type
    return mime_types[sizeof(mime_types) / sizeof(mime_types[0]) - 1].mime_type;
}
