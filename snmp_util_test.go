package snmp

import (
	"context"
	"net"
	"os"
	"runtime/pprof"
	"testing"
	"time"
)

type ErrTimeout struct{}

func (e ErrTimeout) Error() string   { return "timeout" }
func (e ErrTimeout) Timeout() bool   { return true }
func (e ErrTimeout) Temporary() bool { return false }

type packet struct {
	p    []byte
	addr net.Addr
}

type ctxC struct {
	ctx    context.Context
	cancel context.CancelFunc
}

func (c *ctxC) from(ctx context.Context) {
	c.ctx, c.cancel = context.WithCancel(ctx)
}

type packetConnStub struct {
	c       ctxC
	in, out chan packet
}

func (stub *packetConnStub) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case pkt := <-stub.in:
		l := len(pkt.p)
		copy(p[:l], pkt.p)
		return l, pkt.addr, nil
	case <-stub.c.ctx.Done():
		return len(p), nil, ErrTimeout{}
	}
}

func (stub *packetConnStub) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	select {
	case stub.out <- packet{p, addr}:
		return len(p), nil
	case <-stub.c.ctx.Done():
		return 0, ErrTimeout{}
	}
}

func (stub *packetConnStub) Close() error                       { panic("not implemented") }
func (stub *packetConnStub) LocalAddr() net.Addr                { panic("not implemented") }
func (stub *packetConnStub) SetDeadline(t time.Time) error      { stub.c.cancel(); return nil }
func (stub *packetConnStub) SetReadDeadline(t time.Time) error  { panic("not implemented") }
func (stub *packetConnStub) SetWriteDeadline(t time.Time) error { panic("not implemented") }

type messageSendEnv struct {
	cmain, cps ctxC
	conn       *packetConnStub
	failMsg    chan error
	ps         *MessageSender
}

type codeLogger func(err error)

func (cl codeLogger) Log(err error) {
	cl(err)
}

func envSetup() (mse *messageSendEnv) {
	mse = &messageSendEnv{}
	mse.cmain.from(context.Background())
	mse.cps.from(mse.cmain.ctx)

	mse.conn = &packetConnStub{
		in:  make(chan packet),
		out: make(chan packet),
	}
	mse.conn.c.from(mse.cmain.ctx)

	mse.failMsg = make(chan error, 1)
	opts := NewMessageSenderOpts().Conn(mse.conn).ChanSize(0).OnErrFunc(func(err error) {
		select {
		case mse.failMsg <- err:
		case <-mse.cps.ctx.Done():
		}
	})
	mse.ps, _ = NewMessageSender(mse.cps.ctx, opts)

	return
}

func (mse *messageSendEnv) stop(t *testing.T, maxWait time.Duration) {
	psClosed := make(chan struct{})
	go func() { mse.ps.Wait(); close(psClosed) }()

	select {
	case <-psClosed:
		break
	case <-time.After(maxWait):
		printstack()
		t.FailNow()
	}
}

func printstack() {
	pprof.Lookup("goroutine").WriteTo(os.Stderr, 1)
}
