#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_log.h>
#include <ngx_times.h>

#include "ngx_http_json_kss_module.h"
#include "parson.h"

// Module and configuration initialization functions.
static ngx_int_t ngx_http_json_kss_init(ngx_conf_t *cf);
static void *ngx_http_json_kss_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_json_kss_merge_log_conf(ngx_conf_t *cf, void *parent,
                                              void *child);

// Log handling and structuring functions.
static ngx_int_t ngx_http_json_kss_log_handler(ngx_http_request_t *r);
static void ngx_http_json_kss_client_headers(JSON_Object *root,
                                             ngx_http_headers_in_t *headers);
static void ngx_http_json_kss_server_headers(JSON_Object *root,
                                             ngx_http_headers_out_t *headers);

// Nginx's ngx_pstrdup doesn't copy the null terminator.
static char *pstrdup0(ngx_pool_t *pool, ngx_str_t *src);

// Allocation wrapper functions for parson.
static void *ngx_http_json_kss_malloc(size_t size);
static void ngx_http_json_kss_free(void *);

static ngx_pool_t *pool = NULL;

// Given an ngx_str_t pointer, return either a new C-string
// containing its data or NULL if the pointer is NULL.
#define PDUP(ngx_str) (ngx_str ? (char *)pstrdup0(pool, (ngx_str)) : NULL)

// Given an ngx_table_elt_t, return a new C-string containing its value.
#define PDUP_ELT(ngx_elt) ((char *)pstrdup0(pool, &(ngx_elt)->value))

// Given a JSON object and an ngx_table_elt_t, place the elt's value
// in the object under the given key. If the elt is NULL,
// place NULL in the tree instead.
#define JSON_SET_ELT_S(json, key, ngx_elt)                                     \
  if (ngx_elt) {                                                               \
    json_object_set_string(json, key, PDUP_ELT(ngx_elt));                      \
  } else {                                                                     \
    json_object_set_null(json, key);                                           \
  }

// Given a JSON object and a pointer to a time_t, place
// the asctime representation of that time_t under the given key.
// If the pointer is NULL, place NULL in the tree instead.
#define JSON_SET_TIME_S(json, key, time)                                       \
  {                                                                            \
    if (time) {                                                                \
      struct tm __tm;                                                          \
      char __buf[26] = {};                                                     \
      gmtime_r(time, &__tm);                                                   \
      asctime_r(&__tm, __buf);                                                 \
      __buf[24] = '\0';                                                        \
      json_object_set_string(json, key, __buf);                                \
    } else {                                                                   \
      json_object_set_null(json, key);                                         \
    }                                                                          \
  }

static ngx_command_t ngx_http_json_kss_commands[] = {
    {
        ngx_string("json_kss"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
            NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_json_kss_loc_conf_t, log_path),
        NULL,
    },
    ngx_null_command,
};

static ngx_http_module_t ngx_http_json_kss_module_ctx = {
    NULL, /* preconfiguration */
    ngx_http_json_kss_init,
    NULL, /* create main configuration */
    NULL, /* init main configuration */
    NULL, /* create server configuration */
    NULL, /* merge server configuration */
    ngx_http_json_kss_create_loc_conf,
    ngx_http_json_kss_merge_log_conf, /* merge location configuration */
};

ngx_module_t ngx_http_json_kss_module = {
    NGX_MODULE_V1,
    &ngx_http_json_kss_module_ctx, /* module context */
    ngx_http_json_kss_commands,    /* module commands */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING,
};

// TODO(ww): It's not clear to me how MT/MP-safe this is.
// Other logging modules (including the default one) don't seem
// to worry at all about race conditions during I/O or I/O
// initialization and Nginx doesn't provide any concurrency
// primitives, so I'm assuming this is fine.
static ngx_http_json_kss_fd_mapping_t
    fd_mapping_cache[NGX_HTTP_JSON_KSS_MAX_LOGS];
static ngx_uint_t fd_mapping_cache_cnt = 0;

static ngx_int_t ngx_http_json_kss_init(ngx_conf_t *cf) {
  ngx_http_handler_pt *h;
  ngx_http_core_main_conf_t *cmcf;

  cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

  h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);

  if (h == NULL) {
    return NGX_ERROR;
  }

  *h = ngx_http_json_kss_log_handler;

  pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, cf->log);

  json_set_allocation_functions(ngx_http_json_kss_malloc,
                                ngx_http_json_kss_free);

  return NGX_OK;
}

static void *ngx_http_json_kss_create_loc_conf(ngx_conf_t *cf) {
  ngx_http_json_kss_loc_conf_t *conf;

  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_json_kss_loc_conf_t));

  if (conf == NULL) {
    return NGX_CONF_ERROR;
  }

  conf->log_path.data = NULL;

  return conf;
}

static char *ngx_http_json_kss_merge_log_conf(ngx_conf_t *cf, void *parent,
                                              void *child) {
  ngx_http_json_kss_loc_conf_t *prev = parent;
  ngx_http_json_kss_loc_conf_t *conf = child;

  ngx_conf_merge_str_value(conf->log_path, prev->log_path,
                           NGX_HTTP_JSON_KSS_DEFAULT_LOG);

  if (fd_mapping_cache_cnt > NGX_HTTP_JSON_KSS_MAX_LOGS) {
    ngx_log_abort(0, "%V: number of unique logfiles exceeds %d",
                  &conf->log_path, NGX_HTTP_JSON_KSS_MAX_LOGS);
  }

  ngx_http_json_kss_fd_mapping_t mapping = {};
  ngx_uint_t i;

  for (i = 0; i < fd_mapping_cache_cnt; i++) {
    if (conf->log_path.len != fd_mapping_cache[i].log_path.len) {
      continue;
    }

    if (ngx_strncmp(conf->log_path.data, fd_mapping_cache[i].log_path.data,
                    conf->log_path.len) == 0) {
      mapping = fd_mapping_cache[i];
      break;
    }
  }

  // Base case: Our log path isn't in the cache already, so add it.
  if (mapping.log_path.data == NULL) {
    fd_mapping_cache[i].log_path = conf->log_path;

    // TODO(ww): Is cf->pool safe here? I can't see why it wouldn't be,
    // but maybe it's better to just do a normal allocation (or a VLA).
    const char *log_path0 = pstrdup0(cf->pool, &conf->log_path);
    fd_mapping_cache[i].fd =
        ngx_open_file(log_path0, NGX_FILE_APPEND, NGX_FILE_CREATE_OR_OPEN,
                      NGX_FILE_DEFAULT_ACCESS);

    if (fd_mapping_cache[i].fd == NGX_INVALID_FILE) {
      ngx_log_stderr(ngx_errno,
                     "[alert] could not open JSON log file: " ngx_open_file_n
                     " \"%s\" failed",
                     log_path0);
      // TODO(ww): Is this a sensible fallback, or should we abort?
      // Aborting would *not* be a serious problem here, as this code
      // runs during nginx startup and exiting on a missing file is
      // probably a reasonable failure condition.
      fd_mapping_cache[i].fd = ngx_stderr;
    }

    fd_mapping_cache_cnt++;
  }

  return NGX_CONF_OK;
}

static ngx_int_t ngx_http_json_kss_log_handler(ngx_http_request_t *r) {
  ngx_http_json_kss_loc_conf_t *conf;
  conf = ngx_http_get_module_loc_conf(r, ngx_http_json_kss_module);

  // TODO(ww): Guard conf?

  JSON_Value *root = json_value_init_object();
  JSON_Object *root_obj = json_value_get_object(root);
  char *json_str = NULL;
  ssize_t json_size = 0;

  json_object_set_value(root_obj, "client", json_value_init_object());
  json_object_set_value(root_obj, "server", json_value_init_object());

  JSON_Object *client = json_object_get_object(root_obj, "client");
  JSON_Object *server = json_object_get_object(root_obj, "server");

  ngx_http_json_kss_client_headers(client, &r->headers_in);
  ngx_http_json_kss_server_headers(server, &r->headers_out);

  json_object_dotset_number(root_obj, "connection.requests",
                            r->connection->requests);

#if (NGX_HTTP_SSL || NGX_COMPAT)
  json_object_dotset_string(root_obj, "connection.ssl_servername",
                            PDUP(r->http_connection->ssl_servername));
#endif

  // NOTE(ww): connection and http_connection are different structures,
  // but separating them in the JSON output would probably be confusing.
  json_object_dotset_boolean(root_obj, "connection.ssl",
                             r->http_connection->ssl);

  // TODO(ww): lingering_time, start_sec, start_msec

  // TODO(ww): Could probably use a static table for all of this.
  json_object_set_number(root_obj, "method", r->method);
  json_object_set_number(root_obj, "http_version", r->http_version);

  json_object_set_string(root_obj, "request_line", PDUP(&r->request_line));
  json_object_set_string(root_obj, "uri", PDUP(&r->uri));
  json_object_set_string(root_obj, "args", PDUP(&r->args));
  json_object_set_string(root_obj, "exten", PDUP(&r->exten));
  json_object_set_string(root_obj, "unparsed_uri", PDUP(&r->unparsed_uri));

  json_object_set_string(root_obj, "method_name", PDUP(&r->method_name));
  json_object_set_string(root_obj, "http_protocol", PDUP(&r->http_protocol));

  // TODO(ww): All kinds of other flags: pipelining, chunked, header_only,
  // expect_trailers, keepalive, lingering_close, etc.

  // TODO(ww): It looks like the default logger gets the timestamp
  // via ngx_timeofday(), which is really just a macro for a cached
  // ngx_time_t (which gets updated via a timer?). So we should expose
  // that as well.

  ngx_http_json_kss_fd_mapping_t mapping = {};
  ngx_uint_t i;

  for (i = 0; i < fd_mapping_cache_cnt; i++) {
    if (conf->log_path.len != fd_mapping_cache[i].log_path.len) {
      continue;
    }

    if (ngx_strncmp(conf->log_path.data, fd_mapping_cache[i].log_path.data,
                    conf->log_path.len) == 0) {
      mapping = fd_mapping_cache[i];
      break;
    }
  }

  // Something has gone terribly wrong, and we're trying to log
  // to a file that was never visited during configuration.
  if (mapping.log_path.data == NULL) {
    ngx_log_abort(0, "attempted to log to an unopened file");
  }

  json_str = json_serialize_to_string(root);
  json_size = strlen(json_str);

  if (ngx_write_fd(mapping.fd, json_str, json_size) != json_size) {
    ngx_log_stderr(ngx_errno,
                   "[alert] partial write to log file: " ngx_write_fd_n
                   " \"%V\" failed",
                   &mapping.log_path);
  }

  // In any case, (try to) write a newline.
  // TODO(ww): Remove this and use NGX_LINEFEED / NGX_LINEFEED_SIZE /
  // ngx_linefeed above to add the newline to the buffer directly.
  ngx_write_fd(mapping.fd, "\n", 1);

  ngx_reset_pool(pool);

  return NGX_OK;
}

static void ngx_http_json_kss_client_headers(JSON_Object *client,
                                             ngx_http_headers_in_t *headers) {
  {
    json_object_set_value(client, "headers", json_value_init_object());
    JSON_Object *hdrs = json_object_get_object(client, "headers");

    ngx_uint_t i;
    ngx_list_part_t *part = &headers->headers.part;
    ngx_table_elt_t *elt = part->elts;

    for (i = 0;; i++) {
      if (i >= part->nelts) {
        if (part->next == NULL) {
          break;
        }

        part = part->next;
        elt = part->elts;
        i = 0;
      }

      json_object_set_string(hdrs, PDUP(&elt[i].key), PDUP(&elt[i].value));
    }
  }

  JSON_SET_ELT_S(client, "host", headers->host);
  JSON_SET_ELT_S(client, "connection", headers->connection);
  JSON_SET_ELT_S(client, "if_modified_since", headers->if_modified_since);
  JSON_SET_ELT_S(client, "if_unmodified_since", headers->if_unmodified_since);
  JSON_SET_ELT_S(client, "if_match", headers->if_match);
  JSON_SET_ELT_S(client, "if_none_match", headers->if_none_match);
  JSON_SET_ELT_S(client, "user_agent", headers->user_agent);
  JSON_SET_ELT_S(client, "referer", headers->referer);
  JSON_SET_ELT_S(client, "content_length", headers->content_length);

// NOTE(ww): 1.15.6 introduces explicit fields for `content_range` and `te`
#if defined(nginx_version) && nginx_version >= 1015006
  JSON_SET_ELT_S(client, "content_range", headers->content_range);
  JSON_SET_ELT_S(client, "te", headers->te);
#endif

  JSON_SET_ELT_S(client, "content_type", headers->content_type);

  JSON_SET_ELT_S(client, "range", headers->range);
  JSON_SET_ELT_S(client, "if_range", headers->if_range);

  JSON_SET_ELT_S(client, "transfer_encoding", headers->transfer_encoding);
  JSON_SET_ELT_S(client, "expect", headers->expect);
  JSON_SET_ELT_S(client, "upgrade", headers->upgrade);

#if (NGX_HTTP_GZIP || NGX_HTTP_HEADERS)
  JSON_SET_ELT_S(client, "accept_encoding", headers->accept_encoding);
  JSON_SET_ELT_S(client, "via", headers->via);
#endif

  JSON_SET_ELT_S(client, "authorization", headers->authorization);
  JSON_SET_ELT_S(client, "keep_alive", headers->keep_alive);

#if (NGX_HTTP_X_FORWARDED_FOR)
  {
    json_object_set_value(client, "x_forwarded_for", json_value_init_array());
    JSON_Array *xff = json_object_get_array(client, "x_forwarded_for");

    ngx_uint_t i;
    ngx_table_elt_t **elt = headers->x_forwarded_for.elts;
    for (i = 0; i < headers->x_forwarded_for.nelts; i++) {
      json_array_append_string(xff, PDUP(&elt[i]->value));
    }
  }
#endif

#if (NGX_HTTP_REALIP)
  JSON_SET_ELT_S(client, "x_real_ip", headers->x_real_ip);
#endif

#if (NGX_HTTP_HEADERS)
  JSON_SET_ELT_S(client, "accept", headers->accept);
  JSON_SET_ELT_S(client, "accept_language", headers->accept_language);
#endif

#if (NGX_HTTP_DAV)
  JSON_SET_ELT_S(client, "dav_depth", headers->depth);
  JSON_SET_ELT_S(client, "dav_destination", headers->destination);
  JSON_SET_ELT_S(client, "dav_overwrite", headers->overwrite);
  JSON_SET_ELT_S(client, "dav_date", headers->date);
#endif

  json_object_set_string(client, "user", PDUP(&headers->user));
  json_object_set_string(client, "passwd", PDUP(&headers->passwd));

  // NOTE(ww): Nginx doesn't appear to split cookies into key/pair values.
  {
    json_object_set_value(client, "cookies", json_value_init_object());
    JSON_Object *cookies = json_object_get_object(client, "cookies");

    ngx_uint_t i;
    ngx_table_elt_t **elt = headers->cookies.elts;

    for (i = 0; i < headers->cookies.nelts; i++) {
      json_object_set_string(cookies, PDUP(&elt[i]->key), PDUP(&elt[i]->value));
    }
  }

  json_object_set_string(client, "server", PDUP(&headers->server));
  json_object_set_number(client, "content_length_n", headers->content_length_n);

  JSON_SET_TIME_S(client, "keep_alive_n", &headers->keep_alive_n);

  char *conntype = "keep-alive";
  if (headers->connection_type == NGX_HTTP_CONNECTION_CLOSE) {
    conntype = "close";
  }
  json_object_set_string(client, "connection_type", conntype);
  json_object_set_boolean(client, "chunked", headers->chunked);

  // TODO(ww): Remove the dotsets here by creating the object explicitly.
  json_object_dotset_boolean(client, "ua.msie", headers->msie);
  json_object_dotset_boolean(client, "ua.msie6", headers->msie6);
  json_object_dotset_boolean(client, "ua.opera", headers->opera);
  json_object_dotset_boolean(client, "ua.gecko", headers->gecko);
  json_object_dotset_boolean(client, "ua.chrome", headers->chrome);
  json_object_dotset_boolean(client, "ua.safari", headers->safari);
  json_object_dotset_boolean(client, "ua.konqueror", headers->konqueror);
}

static void ngx_http_json_kss_server_headers(JSON_Object *server,
                                             ngx_http_headers_out_t *headers) {
  {
    json_object_set_value(server, "headers", json_value_init_object());
    JSON_Object *hdrs = json_object_get_object(server, "headers");

    ngx_uint_t i;
    ngx_list_part_t *part = &headers->headers.part;
    ngx_table_elt_t *elt = part->elts;

    for (i = 0;; i++) {
      if (i >= part->nelts) {
        if (part->next == NULL) {
          break;
        }

        part = part->next;
        elt = part->elts;
        i = 0;
      }

      json_object_set_string(hdrs, PDUP(&elt[i].key), PDUP(&elt[i].value));
    }
  }

  json_object_set_string(server, "status_line", PDUP(&headers->status_line));

  JSON_SET_ELT_S(server, "server", headers->server);
  JSON_SET_ELT_S(server, "date", headers->date);
  JSON_SET_ELT_S(server, "content_length", headers->content_length);
  JSON_SET_ELT_S(server, "content_encoding", headers->content_encoding);
  JSON_SET_ELT_S(server, "location", headers->location);
  JSON_SET_ELT_S(server, "refresh", headers->refresh);
  JSON_SET_ELT_S(server, "refresh", headers->refresh);
  JSON_SET_ELT_S(server, "last_modified", headers->last_modified);
  JSON_SET_ELT_S(server, "content_range", headers->content_range);
  JSON_SET_ELT_S(server, "accept_ranges", headers->accept_ranges);
  JSON_SET_ELT_S(server, "www_authenticate", headers->www_authenticate);
  JSON_SET_ELT_S(server, "expires", headers->expires);
  JSON_SET_ELT_S(server, "etag", headers->etag);

  json_object_set_string(server, "override_charset",
                         PDUP(headers->override_charset));

  json_object_set_string(server, "content_type", PDUP(&headers->content_type));
  json_object_set_string(server, "charset", PDUP(&headers->charset));

  json_object_set_number(server, "content_length_n", headers->content_length_n);
  json_object_set_number(server, "content_offset", headers->content_offset);

  // TODO(ww): cache-control, link

  JSON_SET_TIME_S(server, "date_time", &headers->date_time);
  JSON_SET_TIME_S(server, "last_modified_time", &headers->last_modified_time);
}

static char *pstrdup0(ngx_pool_t *pool, ngx_str_t *src) {
  if (pool == NULL) {
    ngx_log_abort(0, "memory pool is NULL?");
  }

  char *dst = ngx_pnalloc(pool, src->len + 1);

  if (dst == NULL) {
    return NULL;
  }

  ngx_memcpy(dst, src->data, src->len);
  dst[src->len] = '\0';

  return dst;
}

static void *ngx_http_json_kss_malloc(size_t size) {
  if (pool == NULL) {
    ngx_log_abort(0, "JSON memory pool is NULL?");
  }

  return ngx_palloc(pool, size);
}

static void ngx_http_json_kss_free(void *ptr) {
  if (pool == NULL) {
    ngx_log_abort(0, "JSON memory pool is NULL?");
  }

  // Do nothing here, since we reset the pool after each request.
}
