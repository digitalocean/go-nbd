# <p align=center>go-nbd</p>

<p align=center>
NBD client implementation in Go, free of any CGO or system-specific
dependencies.
</p>

<hr />

<p align=center>:warning:</p>

go-nbd implements enough of the NBD protocol specification[^1] to be useful
in some general circumstances, but it is not an exhaustive and complete
implementation (yet.) For example, it does not initiate a hard disconnect
from the server in all instances where the specification states the client
MUST initiate a hard disconnect.

For more information, see [unimplemented](#unimplemented).

<hr />

## Goals

* Implement enough of the client-side of the Network Block Device protocol
  to be generally useful.
* No dependencies on CGO, header files, or other platform-specific things.

## Unimplemented

If you have a use-case for any of these things, please file an issue.

* Old-style option negotation is specifically not supported.
* `NBD_OPT_PEEK_EXPORT` - The protocol spec describes this as withdrawn and not
in use.
* `NBD_OPT_STARTTLS` - This module's Dialer has rudimentary though untested
support for dialing over TLS.
* `NBD_CMD_RESIZE` - The protocol spec describes this as defined by an experimental
`RESIZE` extension.
* `EXTENDED_HEADER` extension - the initial release of this module is targeting only
the base Network Block Device protocol.
* `RESIZE` extension - the initial release of this module is targeting only
the base Network Block Device protocol.

## Security

Please see [SECURITY.md](https://github.com/digitalocean/go-nbd/security/policy) for
information on reporting security-related concerns to DigitalOcean's security team.

Thank you!

## Tutorial

First, you'll want to dial an NBD server to construct an nbd.Conn:

```go
uri := nbd.MustURI(os.Getenv("EXAMPLE_NBD_URI"))
var dialer nbd.Dialer
conn, err := dialer.Dial(context.TODO(), uri)
if err != nil {
    return fmt.Errorf("nbd dial: %w", err)
}
defer conn.Close()
```

At which point, you'll want to complete the NBD handshake before
negotiating options:

```go
err = conn.Connect()
if err != nil {
    return fmt.Errorf("nbd connect: %w", err)
}
defer conn.Abort()
```

If the call to Connect is successful, your nbd.Conn is now in the
option negotiation phase. In this phase, you can call the following
methods on your nbd.Conn:

```go
func (c *Conn) Abort() error
func (c *Conn) Close() error
func (c *Conn) ExportName(name string) (size uint64, flags TransmissionFlags, err error)
func (c *Conn) Go(name string, requests []InfoRequest) (ExportInfo, error)
func (c *Conn) Info(name string, requests []InfoRequest) (ExportInfo, error)
func (c *Conn) List() (exports []string, err error)
func (c *Conn) ListMetaContext(export string, queries ...string) ([]MetaContext, error)
func (c *Conn) SetMetaContext(export string, query string, additional ...string) ([]MetaContext, error)
func (c *Conn) StructuredReplies() error
```

Note that successful execution of the following methods will transition
the nbd.Conn into the transmission phase:

```go
func (c *Conn) ExportName(name string) (size uint64, flags TransmissionFlags, err error)
func (c *Conn) Go(name string, requests []InfoRequest) (ExportInfo, error)
```

<p align=center>:warning: Don't forget to <code>defer conn.Disconnect()</code> after entering the
transmission phase! :warning:</p>

Once in the transmission phase, you can call the following methods on the
nbd.Conn:

```go
func (c *Conn) Abort() error
func (c *Conn) BlockStatus(flags CommandFlags, offset uint64, length uint32) (BlockStatus, error)
func (c *Conn) Cache(flags CommandFlags, offset uint64, length uint32) error
func (c *Conn) Close() error
func (c *Conn) Disconnect() error
func (c *Conn) Flush(flags CommandFlags) error
func (c *Conn) Read(flags CommandFlags, offset uint64, length uint32) ([]Read, error)
func (c *Conn) Trim(flags CommandFlags, offset uint64, length uint32) error
func (c *Conn) Write(flags CommandFlags, offset uint64, data []byte) error
func (c *Conn) WriteZeroes(flags CommandFlags, offset uint64, length uint32) error
```

## FAQ

> Is it safe to interact with the Conn object from multiple goroutines?

Prefer instead to see if the server supports multiple connections by seeing if
it sets the TransmissionFlagCanMultiConn bit in its transmission flags. If it
does, use nbd.Dialer to create additional Conns and negotiate the same options as
before.

You can get a copy of the transmission flags by calling Conn.Info (a read-only
operation that does not transition the connection into transmission phase),
or by calling one of: Conn.Go, Conn.ExportName.

Note that the NBD protocol spec requires clients to perform the option negotation
phase synchronously. This module does not have any guardrails against client code
violating this constraint by invoking option negotiation methods on an nbd.Conn
from multiple goroutines.

> What is the difference between Conn.Abort, Conn.Disconnect, and Conn.Close?

* Conn.Close closes the underlying transport.
* Conn.Abort politely terminates the option phase with the server. It is
  a no-op if the connection has transitioned to the transmission phase.
* Conn.Disconnect politely terminates the transmission phase with the server.

These are intended to work conveniently with client code defer statements
to tear down the connection in the reverse order that it was brought up.

For example (error handling omitted for brevity):

```go
uri := nbd.MustURI(os.Getenv("EXAMPLE_NBD_URI"))

// nbd.Dialer opens the underlying transport (TCP, UNIX),
// so conn.Close will close the transport connection.
var dialer nbd.Dialer
conn, _ := dialer.Dial(context.TODO(), uri)
defer conn.Close()

// conn.Connect performs the NBD handshake and begins
// the option phase, so conn.Abort will politely terminate
// this phase with the server (or no-op if the Conn has
// transitioned into the transmission phase.)
_ = conn.Connect()
defer conn.Abort()

// conn.Go or conn.ExportName transition the Conn into the
// transmission phase, so conn.Disconnect will politely
// terminate this phase with the server.
_, _ = conn.Go("vda", nbd.InfoRequestAll())
defer conn.Disconnect()
```

[^1]: https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md
