nginx-json-kss
==============

Painless JSON logging for Nginx.

## Usage

By default, the module will log to `/var/log/nginx/access.jsonl`, one JSON record
per line. You can change this on global, per-server, or per-location basis:

```nginx
http {
    json_kss /tmp/global.jsonl;

    server {
        listen 80 default_server;
        json_kss /tmp/server.jsonl;

        location /special_location {
            json_kss /tmp/location.jsonl;
        }
    }
}
```

More specific specifications always take precedence, meaning that a request
to `/special_location` on port 80 will *only* be logged in `/tmp/location.jsonl` and
not any higher-up logs.
