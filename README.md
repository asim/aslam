# aslam

personal server

## Overview

What if you could run everything yourself? DNS, email, storage, etc. Would it be worth it? Let's find out.

I'm going to start hacking on a personal server that's built from scratch. The ideal bootstrapping scenario 
is to buy a domain name, start this server and point the nameserver to it, then leave it to do it's thing.

## Features

- [ ] DNS server (DNS)
- [ ] Email server (SMTP)
- [ ] File server (FTP)
- [ ] Web server (HTTP)
- [ ] Chat server (XMPP)
- [ ] Socks proxy (SOCKS5)
- [ ] Virtual network (VPN)

## Stretch Goals

- [ ] DigitalOcean Deployment
- [ ] Raspberry Pi Bootloader
- [ ] Android APK Image

## Usage

It's a Go binary and everything is currently just configured via env vars.

### Install

```
go build -o aslam main.go
```

### Env vars

There's a few env vars to specify

- `DOMAIN` - The domain you want to administer e.g asl.am
- `ADDRESS` - The public ip address of the server e.g 1.2.3.4
- `DNS_SERVERS` - To support external DNS queries e.g 8.8.8.8:53

### Config

There is support for a config file. Config found in `$HOME/.aslam/config.json` will be loaded.

```
{
        "domain": "asl.am",
        "address": "1.2.3.4",
	"dns_servers": ["8.8.8.8:53"]
}
```

Env vars will continue to override the config file

### Start server

Run the server

```
DOMAIN=asl.am ADDRESS=1.2.3.4 ./aslam
```

### Port usage

Ports used

- 1025 - for SMTP
- 1080 - for SOCKS5
- 5353 - for DNS
- 8080 - for HTTP

## Testing

### DNS

```
# A record
dig @127.0.0.1 -p 5353 asl.am A

# MX record
dig @127.0.0.1 -p 5353 asl.am MX
```

### Web

```
curl http://localhost:8080
```

### Email

```
telnet localhost 1025
Trying ::1...
Connected to localhost.
Escape character is '^]'.
220 asl.am ESMTP Service Ready
mail from: asim@example.com
502 2.5.1 Please introduce yourself first.
helo foo
250 2.0.0 Hello foo
mail from: asim@example.com
250 2.0.0 Roger, accepting mail from <asim@example.com>
rcpt to: asim@asl.am
250 2.0.0 I'll make sure <asim@asl.am> gets this
data
354 2.0.0 Go ahead. End your data with <CR><LF>.<CR><LF>
yo dude

.
250 2.0.0 OK: queued
quit
```

## DNS

The DNS server acts as an authoritative nameserver for the domain specified, so it will serve the address 
specified for the domain name e.g `DOMAIN=asl.am` and `ADDRESS=1.2.3.4` will mean any query for asl.am 
will return 1.2.3.4. This will occur for `A` and `MX` record queries.

### External DNS

Additionally we can support external DNS queries via a secondary source e.g `1.1.1.1` or `8.8.8.8`.

Set `DNS_SERVERS=1.1.1.1:53` to support non authoritative queries for external DNS records.

## Storage

### Email

Email is stored in `$HOME/.aslam/mail`. Each email is a unix nano timestamped file with `.txt` extension.

Mail reader coming soon.

### Web

The HTTP server is a static web server that reads from `$HOME/.aslam/web`. A template index.html file is 
created on startup if no previous directory is found.

## TODO

- [ ] Simple web editing might be nice
- [ ] Prod flag to switch to live ports
- [ ] Email sender validation for domain
- [ ] User accounts and authentication
- [ ] Multi tenant architecture...???
