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

## Usage

It's a Go binary and everything is currently just configured via env vars.

```
go build -o aslam main.go
```

There's a few env vars to specify

- `DOMAIN` - The domain you want to administer
- `ADDRESS` - The public ip address of the server
- `HOME` - The home directory used for storage

Run the server

```
./aslam
```

Ports used

- 1025 - for SMTP
- 5353 - for DNS

Test the DNS

```
dig @127.0.0.1 -p 5353 asl.am.
```

Test the email

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
