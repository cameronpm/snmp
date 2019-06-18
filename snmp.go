package snmp

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"net"
	"sync"
	"time"

	"golang.org/x/xerrors"
)

type ErrMalformedResponse struct {
	ExpOIDs int
	GotOIDs int
}

func (e *ErrMalformedResponse) Error() string {
	return fmt.Sprintf("Expected %d OIDs in response, got %d", e.ExpOIDs, e.GotOIDs)
}

// MessageRequest represents a single SNMP request (with some special-case
// conditions for bulk walks). The response may be sent either to the .Response
// or .C attributes.
type MessageRequest struct {
	Addr    net.Addr // Destination address. Should be *net.UDPAddr unless testing
	Message *Message // Source message

	// Response is called when a response comes in. If not nil, it will be
	// called on the main thread. If it blocks, then the SNMP operations will
	// block (so be fast!).
	Response func(response MessageResponse)
	// C is a channel created by the user. If it is not nil, it messages will be
	// sent to it. If it blocks then SNMP operations will block (so be fast!)
	C chan MessageResponse

	// timer stores the action on timeout for a single SNMP packet as determined
	// by timeoutAfter, on timeout, either retries or removes PDU requestId from
	// MessageSender.active map, depending on attempts
	timer        *time.Timer
	attempts     int           // used for retry and timeout tracking that ultimately sends ErrTimedOut responses
	timeoutAfter time.Duration // period to wait before resending SNMP packet
}

// Retries is called when you want to modify the default retry and timeout behavior of
// individual SNMP requests. If not called, defaults to being called as:
//   mr.Retries(2, time.Second)
func (mr *MessageRequest) Retries(retries int, timeoutAfter time.Duration) {
	mr.attempts = retries + 1
	mr.timeoutAfter = timeoutAfter
}

func (mr *MessageRequest) send(ctx context.Context, inline bool, pRes MessageResponse) {
	if mr.Response != nil {
		if inline {
			mr.Response(pRes)
		} else {
			go mr.Response(pRes)
		}
	}
	if mr.C != nil {
		select {
		case <-ctx.Done():
		case mr.C <- pRes:
		}
	}
}

func (mr *MessageRequest) setRetryCallback(ms *MessageSender) {
	if mr.attempts == 0 {
		panic("internal error")
	}

	mr.attempts--
	mr.timer = time.AfterFunc(mr.timeoutAfter, func() {
		// Quick check if not shut down
		select {
		case <-ms.ctx.Done():
			return
		default:
		}

		rid := int32(mr.Message.Pdu.RequestId())
		ms.activeMu.Lock()
		_, ok := ms.active[rid]
		if ok {
			delete(ms.active, rid)
		}
		ms.activeMu.Unlock()

		if !ok {
			// Race condition. If it did not exist in ps.active, then it was
			// removed for a legit reason
			return
		}

		if mr.attempts == 0 {
			mr.send(ms.ctx, ms.cbInline, MessageResponse{
				Request: mr.Message,
				Err:     ErrTimedOut,
			})
			return
		}

		select {
		case <-ms.ctx.Done():
		case ms.MC <- mr:
		}
	})
}

// MessageResponse is sent to the MessageRequest.Response or MessageRequest.C attrs. Either
// Response or Err will be non-nil, not both/neither.
type MessageResponse struct {
	Request  *Message // the original request
	Response *Message // full response. If non-nil, then Err is nil
	Err      error    // may be either ErrTimedOut or ErrWalkSingleOid
}

// MessageSender is the controller for all SNMP operations. SNMP message requests are sent to
type MessageSender struct {
	MC chan *MessageRequest
	TC chan *TableRequest

	conn     net.PacketConn
	ctx      context.Context
	cancel   context.CancelFunc
	onErr    ErrorLogger
	cbInline bool

	active   map[int32]*MessageRequest
	activeMu sync.Mutex

	wg sync.WaitGroup
}

func NewMessageSenderOpts() *MessageSenderOpts {
	msg := &MessageSenderOpts{}
	return msg.init()
}

type MessageSenderOpts struct {
	_init    bool
	chanSize int
	conn     net.PacketConn
	onErr    ErrorLogger
	cbInline bool
}

func (o *MessageSenderOpts) init() *MessageSenderOpts {
	if !o._init {
		o._init = true
		o.chanSize = DefaultChanSize
		o.conn = nil
		o.onErr = DefaultErrorLogger
		o.cbInline = false
	}
	return o
}

// ChanSize (which defaults to DefaultChanSize) controls the queue size of
// MessageSender.MC and MessageSender.TC. Setting this to 0 will cause
// the queue to become blocking.
func (o *MessageSenderOpts) ChanSize(sz int) *MessageSenderOpts {
	o.chanSize = sz
	return o
}

// Conn is the socket on which all UDP packets will be sent. By default,
// it binds to UDP ':0', which will create a UDP socket on an ephemeral port
// which will be in the range (on Linux) as per this command:
//   sysctl net.ipv4.ip_local_port_range
func (o *MessageSenderOpts) Conn(conn net.PacketConn) *MessageSenderOpts {
	o.conn = conn
	return o
}

// OnErr provides an interface for logging all errors. By default it uses the
// 'log' package. If you wish to provide a code callback, use OnErrFunc instead
func (o *MessageSenderOpts) OnErr(onErr ErrorLogger) *MessageSenderOpts {
	o.onErr = onErr
	return o
}

// OnErr provides an interface for logging all errors. By default it uses the
// 'log' package. This method allows a func instead of interface
func (o *MessageSenderOpts) OnErrFunc(onErr func(error)) *MessageSenderOpts {
	o.onErr = logErrFunc(onErr)
	return o
}

// CallbackInline controls whether each MessageRequest.Response Callback is
// called in its own goroutine, or on the main goroutine. If you are leaving
// the .Response attr nil and only using channels then this is irrelevant.
//
// By default this is false, each callback will run on its goroutine.
func (o *MessageSenderOpts) CallbackInline(inline bool) *MessageSenderOpts {
	o.cbInline = inline
	return o
}

type logErrFunc func(error)

func (e logErrFunc) Log(err error) {
	e(err)
}

// NewMessageSenderWithConn sets up *MessageSender to allow sending and receiving of SNMP messages
// asynchronously from a socket.
//
// Param ctx will gracefully shut down all goroutines created by this method call.
// Calling MessageSender.Wait() will will block until all goroutines have exited.
//
// If 'opts' is nil, sensible tunable defaults will be used however internal error messages
// will be sent using the 'log' interface
func NewMessageSender(ctx context.Context, opts *MessageSenderOpts) (*MessageSender, error) {
	if opts == nil {
		opts = NewMessageSenderOpts()
	}
	opts.init()
	conn := opts.conn
	if conn == nil {
		var err error
		conn, err = net.ListenPacket("udp", ":0")
		if err != nil {
			return nil, err
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	ms := &MessageSender{
		conn:     conn,
		ctx:      ctx,
		cancel:   cancel,
		active:   make(map[int32]*MessageRequest),
		onErr:    opts.onErr,
		cbInline: opts.cbInline,
		MC:       make(chan *MessageRequest, opts.chanSize),
		TC:       make(chan *TableRequest, opts.chanSize),
	}
	ms.wg.Add(4)
	go ms.deadlineOnCancel()
	go ms.messageChanListener()
	go ms.tableChanListener()
	go ms.onRecv()
	return ms, nil
}

// Wait blocks until all goroutines created by NewMessageSenderWithConn have
// shut down. That shutdown will happen when the context provided to it closes.
func (ms *MessageSender) Wait() { ms.wg.Wait() }

func (ms *MessageSender) deadlineOnCancel() {
	defer ms.wg.Done()
	<-ms.ctx.Done()
	ms.conn.SetDeadline(time.Now())
}

func (ms *MessageSender) messageChanListener() {
	defer ms.wg.Done()
	reqID := rand.Int31()

	for {
		select {
		case <-ms.ctx.Done():
			return
		case req := <-ms.MC:
			if req.attempts == 0 {
				req.Retries(defaultRetry, defaultRetryAfter)
			}
			if reqID == math.MaxInt32 {
				reqID = 0
			} else {
				reqID++
			}
			req.Message.Pdu.SetRequestId(int(reqID))
			buf, err := req.Message.Marshal()
			if err != nil {
				req.send(ms.ctx, ms.cbInline, MessageResponse{
					Request: req.Message,
					Err:     err,
				})
				continue
			}
			ms.activeMu.Lock()
			ms.active[reqID] = req
			ms.activeMu.Unlock()
			req.setRetryCallback(ms)
			if _, err := ms.conn.WriteTo(buf, req.Addr); err != nil {
				req.send(ms.ctx, ms.cbInline, MessageResponse{
					Request: req.Message,
					Err:     err,
				})
				ms.activeMu.Lock()
				delete(ms.active, reqID)
				ms.activeMu.Unlock()
				req.timer.Stop()
			}
		}
	}
}

func (ms *MessageSender) onRecv() {
	defer ms.wg.Done()
	var buf [65536]byte
	for {
		n, addr, err := ms.conn.ReadFrom(buf[:])
		if err != nil {
			// Most likely because err.(net.Error).Timeout() == true
			// At this point not much we care about.
			select {
			case <-ms.ctx.Done():
				return
			default:
			}
			ms.cancel()
			ms.onErr.Log(xerrors.Errorf("error reading from socket: %w", err))
			return
		}
		res := &Message{}
		if _, err := res.Unmarshal(buf[:n]); err != nil {
			ms.onErr.Log(xerrors.Errorf("[%s] unable to parse inbound SNMP packet of len %d: %w", addr, n, err))
			continue
		}
		req := ms.findReq(addr, res)

		if req == nil {
			continue
		}
		if req.timer != nil {
			req.timer.Stop()
			req.timer = nil
		}

		req.send(ms.ctx, ms.cbInline, MessageResponse{
			Request:  req.Message,
			Response: res,
		})
	}
}

func (ms *MessageSender) findReq(addr net.Addr, res *Message) *MessageRequest {
	ms.activeMu.Lock()
	defer ms.activeMu.Unlock()

	//fmt.Printf("findReq(): looking for %d in tab size %d\n", res.Pdu.RequestId(), len(ms.active))
	req, ok := ms.active[int32(res.Pdu.RequestId())]
	if !ok {
		// i wonder what caused this?
		return nil
	}

	if a1, ok := addr.(*net.UDPAddr); !ok {
		if a2, ok := req.Addr.(*net.UDPAddr); ok {
			if a1.IP.Equal(a2.IP) && a1.Port == a2.Port && a1.Zone == a2.Zone {
				goto equal
			}
			ms.onErr.Log(xerrors.Errorf("[%s] requestId to UDP address, wanted %s", addr, req.Addr))
			return nil
		}
	}

	if addr.String() != req.Addr.String() {
		ms.onErr.Log(xerrors.Errorf("[%s] requestId to address, wanted %s", addr.String(), req.Addr))
		return nil
	}

equal:
	if req.timer != nil {
		req.timer.Stop()
	}
	delete(ms.active, int32(res.Pdu.RequestId()))
	return req
}
