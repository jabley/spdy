# SPDY

A learning exercise in implementing a [network protocol](http://www.chromium.org/spdy/spdy-protocol/spdy-protocol-draft2) in Go.

# Testing

Done interactively using `transport_test.go` along with the tools in
`examples` to generate a self-signed cert and have a local server.

# Disclaimer

As a learning exercise, I didn't TDD this, but drove it using a single
end-to-end test.

As such, I would not consider this production-ready code. There was
liberal use of the `notImplemented()` function to get to the point
where it works.

Writing this code suggested to me that it might be nice to have a
implementers package in `net/http` which exposes some of the things
like connection pooling. The [existing fallback](https://github.com/jabley/spdy/blob/3ebe0224f91c066c52a7ce4d77f929ef32a1beac/transport.go#L63-L81) for https doesn't
have niceties like that.

It's also not finished. It doesn't support PUT and POST, for example.
I'm not sure I will do that. For my purposes, GET is all that I need to
pull data out of various [backing services](http://12factor.net/backing-services). I would also want to
write tests before having the confidence to run it in production.

I'm hopeful that I will be able to use HTTP/2 in production in near
future, so there seems little point in making that investment in this
project.

# Acknowledgements

I've read Brad Fitzpatrick's HTTP/2 and Jamie Hall's SPDY implementation. A lot of
the code is derived from those.
