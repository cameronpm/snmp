package snmp

import (
	"context"
	"net"
	"time"

	"github.com/k-sone/snmpgo"
)

const DefaultMaxRepetitions = 10

type TableRequest struct {
	// Context for cancellation. If nil, uses the context of the MessageSender. Cancelling
	// this context will prevent messages being sent using the channel C, but the Response
	// function will be called regardless
	Context context.Context

	Addr      net.Addr    // Destination address. Should be *net.UDPAddr unless testing
	Community []byte      // Host's community string
	SnmpV1    bool        // SNMP version, only v1 and v2c are supported
	Oids      snmpgo.Oids // Table base OIDs to fetch

	TimeoutAfter time.Duration // Timeout for each request
	StopAfter    time.Time     // Stop request resends after this time
	MaxRep       int           // defaults to DefaultMaxRepetitions when using GetBulk
	Slow         bool          // when true, uses GetNext instead of GetBulk

	// Update (when non-nil) will be called after each SNMP request/response,
	// and allow the caller to update MaxRep if requested. This is useful when
	// experimenting with increasing the MaxRep field to decrease roundtrip times, and
	// compensating for that if packets are being dropped
	//
	// In the Update call, you can alter MaxRep and TimeoutAfter and it will take effect in
	// the next SNMP packet. Return true to stop further processing.
	Update func(tr *TableRequest, failure bool, took time.Duration) (stop bool)

	// Response is called when a response comes in. If not nil, it will be
	// called on the main thread. If it blocks, then the SNMP operations will
	// block (so be fast!).
	Response func(response TableResponse)
	// C is a channel created by the user. If it is not nil, it messages will be
	// sent to it. If it blocks then SNMP operations will block (so be fast!)
	C chan TableResponse
}

type TableResponse struct {
	Request  *TableRequest
	VarBinds []snmpgo.VarBinds // Responses corresponding to the indices of the OIDs in the request
	// Err may be one of the following:
	//    ErrTimedOut
	//    ErrWalkSingleOid
	//    context.Canceled
	//    context.DeadlineExceeded
	//
	// This differs in behavior to MessageResponse.Err in that a new context can be
	// passed into GetTableSlow or GetTable, allowing cancellation or deadlines
	// to occur which will be passed back. This increase in functionality is allowed
	// as this is a higher level API which builds on the MessageRequest primitives
	Err error

	Timeouts      int             // number of sub-requests that timed out
	ResponseTimes []time.Duration // times of responses that did not time out
}

func (tr *TableResponse) TimedOut() bool {
	return tr.Err == ErrTimedOut || tr.Err == context.DeadlineExceeded
}

func (tr *TableRequest) send(ctx context.Context, varbinds []snmpgo.VarBinds, err error,
	timeouts int, responseTimes []time.Duration,
) {
	tRes := TableResponse{
		Request:       tr,
		VarBinds:      varbinds,
		Err:           err,
		Timeouts:      timeouts,
		ResponseTimes: responseTimes,
	}
	if tr.Response != nil {
		tr.Response(tRes)
	}
	if tr.C != nil {
		select {
		case tr.C <- tRes:
		case <-ctx.Done():
		}
	}
}

func (ms *MessageSender) tableChanListener() {
	defer ms.wg.Done()

	for {
		select {
		case <-ms.ctx.Done():
			return
		case req := <-ms.TC:
			if req.Slow || req.SnmpV1 {
				ms.tableChanNewSlowMessage(req)
			} else {
				ms.tableChanNewFastMessage(req)
			}
		}
	}
}

type tableMessageSender struct {
	ctx context.Context
	ms  *MessageSender
	tr  *TableRequest
	vbs []snmpgo.VarBinds
	off []int

	timeouts     int             // each timeout increments this
	took         []time.Duration // duration of all successful requests
	request      MessageRequest  // current sub-request
	requestStart time.Time       // current sub request start time
}

type slowTableMessageSender struct {
	tableMessageSender
	version snmpgo.SNMPVersion
}

func (ms *MessageSender) newTableMessageSender(tr *TableRequest) (tms tableMessageSender) {
	tms.ms = ms
	tms.tr = tr
	tms.ctx = tr.Context
	if tms.ctx == nil {
		tms.ctx = ms.ctx
	}
	tms.vbs = make([]snmpgo.VarBinds, len(tr.Oids))
	tms.off = make([]int, len(tr.Oids))
	for i := range tr.Oids {
		tms.off[i] = i
	}

	tms.request.Addr = tr.Addr
	return tms
}

func (ms *MessageSender) tableChanNewSlowMessage(tr *TableRequest) {
	stms := slowTableMessageSender{tableMessageSender: ms.newTableMessageSender(tr)}

	if tr.SnmpV1 {
		stms.version = snmpgo.V1
	} else {
		stms.version = snmpgo.V2c
	}
	stms.request.Message = NewMessageWithOids(stms.version, snmpgo.GetNextRequest, tr.Community, tr.Oids)
	stms.request.Response = stms.onResponse

	stms.sendMessageRequest()
}

func (tms *tableMessageSender) sendMessageRequest() {
	if tms.tr.TimeoutAfter > 0 {
		after := tms.tr.TimeoutAfter
		if !tms.tr.StopAfter.IsZero() && time.Now().Add(after).After(tms.tr.StopAfter) {
			after = tms.tr.StopAfter.Sub(time.Now())
		}
		tms.request.Retries(0, after)
	} else if !tms.tr.StopAfter.IsZero() {
		tms.request.Retries(0, tms.tr.StopAfter.Sub(time.Now()))
	}
	tms.requestStart = time.Now()
	select {
	case <-tms.ctx.Done():
		tms.tr.send(tms.ctx, nil, tms.ctx.Err(), tms.timeouts, tms.took)
	case tms.ms.MC <- &tms.request:
	}
}

// return true to not continue
func (tms *tableMessageSender) onResponseErrCheck(r MessageResponse) bool {
	took := time.Now().Sub(tms.requestStart)

	var cancel bool
	if tms.tr.Update != nil {
		if tms.tr.Update(tms.tr, r.Err != nil, took) {
			cancel = true
		}
	}
	ctxErr := tms.ctx.Err()
	if r.Err == nil && ctxErr != nil {
		r.Err = ctxErr
	}
	if r.Err != nil {
		if r.Err == ErrTimedOut && tms.tr.TimeoutAfter > 0 {
			tms.timeouts++
			if cancel {
				r.Err = ErrCancelViaUpdate
			} else if ctxErr != nil {
				r.Err = ctxErr
			} else if time.Now().Before(tms.tr.StopAfter) {
				tms.sendMessageRequest()
				return true
			}
		}
		tms.tr.send(tms.ctx, nil, r.Err, tms.timeouts, tms.took)
		return true
	}

	tms.took = append(tms.took, took)
	return false
}

func (stms *slowTableMessageSender) onResponse(r MessageResponse) {
	if stms.onResponseErrCheck(r) {
		return
	}

	next := make(snmpgo.Oids, 0, len(stms.off))
	nextOff := make([]int, 0, len(stms.off))

	pdu := r.Response.Pdu
	pvbs := pdu.VarBinds()

	if len(pvbs) != len(stms.off) {
		stms.tr.send(stms.ctx, nil, &ErrMalformedResponse{
			ExpOIDs: len(stms.off),
			GotOIDs: len(pvbs),
		}, stms.timeouts, stms.took)
		return
	}

	for i, vb := range pvbs {
		idx := stms.off[i]

		switch vb.Variable.(type) {
		case *snmpgo.NoSucheObject: // legal if base OID not implemented
			continue
		case *snmpgo.NoSucheInstance: // shouldn't be possible?
			continue
		case *snmpgo.EndOfMibView: // legal
			continue
		case *snmpgo.Null: // SNMP v1 behavior?
			continue
		}

		if !vb.Oid.Contains(stms.tr.Oids[idx]) {
			continue
		}
		next = append(next, vb.Oid)
		stms.vbs[idx] = append(stms.vbs[idx], vb)
		nextOff = append(nextOff, stms.off[i])
	}
	stms.off = nextOff

	if len(stms.off) == 0 {
		stms.tr.send(stms.ctx, stms.vbs, nil, stms.timeouts, stms.took)
		return
	}

	stms.request.Message = NewMessageWithOids(stms.version, snmpgo.GetNextRequest, stms.tr.Community, next)
	stms.sendMessageRequest()
}

type fastTableMessageSender struct {
	tableMessageSender
	last snmpgo.Oids
}

func (ms *MessageSender) tableChanNewFastMessage(tr *TableRequest) {
	ftms := fastTableMessageSender{tableMessageSender: ms.newTableMessageSender(tr)}

	ftms.last = make(snmpgo.Oids, len(tr.Oids))

	ftms.request.Message = NewMessageWithOids(snmpgo.V2c, snmpgo.GetBulkRequest, tr.Community, tr.Oids)
	ftms.request.Message.Pdu.SetMaxRepetitions(tr.MaxRep)
	ftms.request.Response = ftms.onResponse

	ftms.sendMessageRequest()
}

func (ftms *fastTableMessageSender) onResponse(r MessageResponse) {
	if ftms.onResponseErrCheck(r) {
		return
	}

	pdu := r.Response.Pdu
	pvbs := pdu.VarBinds()

	unhealthy := make([]bool, len(ftms.off))

	for i, vb := range pvbs {
		mI := i % len(ftms.off)
		idx := ftms.off[mI]
		// fmt.Printf("i=%d mI=%d idx=%d vb=%s\n", i, mI, idx, vb)
		if unhealthy[mI] {
			continue
		}

		var bad bool
		switch vb.Variable.(type) {
		case *snmpgo.NoSucheObject: // shouldn't be possible in a getnext/getbulk
			bad = true
		case *snmpgo.NoSucheInstance: // shouldn't be possible in a getnext/getbulk
			bad = true
		case *snmpgo.EndOfMibView: // legal
			bad = true
		case *snmpgo.Null: // SNMP v1 behavior?
			bad = true
		}

		if bad || !vb.Oid.Contains(ftms.tr.Oids[idx]) {
			// fmt.Printf("i=%d mI=%d idx=%d %s does not contain %s\n", i, mI, idx, vb.Oid, tr.Oids[idx])
			unhealthy[mI] = true
			continue
		}

		//idx := off[mI]
		ftms.last[idx] = vb.Oid
		ftms.vbs[idx] = append(ftms.vbs[idx], vb)
	}

	// malloc inefficient, will fix if it ever becomes an issue (it won't)
	next := make(snmpgo.Oids, 0, len(ftms.off))
	nextOff := make([]int, 0, len(ftms.off))
	for i, bad := range unhealthy {
		if !bad {
			idx := ftms.off[i]
			v := ftms.vbs[idx]
			next = append(next, v[len(v)-1].Oid)
			nextOff = append(nextOff, ftms.off[i])
		}
	}

	ftms.off = nextOff

	if len(ftms.off) == 0 {
		ftms.tr.send(ftms.ctx, ftms.vbs, nil, ftms.timeouts, ftms.took)
		return
	}

	ftms.request.Message = NewMessageWithOids(snmpgo.V2c, snmpgo.GetBulkRequest, ftms.tr.Community, next)
	ftms.request.Message.Pdu.SetMaxRepetitions(ftms.tr.MaxRep)
	ftms.sendMessageRequest()
}
