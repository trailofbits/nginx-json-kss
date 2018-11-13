#ifndef __NGX_HTTP_JSON_KSS_MODULE_H__
#define __NGX_HTTP_JSON_KSS_MODULE_H__

#define NGX_JSON_KSS_VER "0.0.1"

// NOTE(ww): This is arbitrary.
// We're caching open files and my guess is that the average use case is going
// to have multiple end points being logged to the same sink, so exceeding
// this probably won't be a practical concern.
#define NGX_HTTP_JSON_KSS_MAX_LOGS 256

// TODO(ww): Should we be providing a default JSON log at all?
#define NGX_HTTP_JSON_KSS_DEFAULT_LOG "/var/log/nginx/access.jsonl"

typedef struct {
  ngx_str_t log_path;
  ngx_fd_t fd;
} ngx_http_json_kss_fd_mapping_t;

typedef struct {
  ngx_str_t log_path;
} ngx_http_json_kss_loc_conf_t;

#endif
