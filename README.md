nginx-json-kss
==============

Painless JSON logging for Nginx.

## Building

`nginx-json-kss` is a standard Nginx module. You can build it by pointing
`nginx`'s `./configure` script at it:

```bash
$ git clone https://github.com/trailofbits/nginx-json-kss
$ cd /path/to/nginx/source
$ ./configure --your-other-options --add-module=/path/to/nginx-json-kss
$ make
$ sudo ./objs/nginx
```

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
