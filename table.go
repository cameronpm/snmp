package snmp

import (
	"context"
	"net"
	"time"

	"github.com/k-sone/snmpgo"
)

const DefaultMaxRepetitions = 10

type TableRequest struct {
	Context      context.Context // If nil, uses the context of the MessageSender
	Addr         net.Addr        // Destination address. Should be *net.UDPAddr unless testing
	Community    []byte          // Host's community string
	SnmpV1       bool            // SNMP version, only v1 and v2c are supported
	Oids         snmpgo.Oids     // Table base OIDs to fetch
	Retries      int
	TimeoutAfter time.Duration

	MaxRep int  // defaults to DefaultMaxRepetitions when using GetBulk
	Slow   bool // when true, uses GetNext instead of GetBulk

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
}

func (tr *TableRequest) send(ctx context.Context, varbinds []snmpgo.VarBinds, err error) {
	tRes := TableResponse{Request: tr, VarBinds: varbinds, Err: err}
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

func (ms *MessageSender) tableChanNewSlowMessage(tr *TableRequest) {
	ctx := tr.Context
	if ctx == nil {
		ctx = ms.ctx
	}
	vbs := make([]snmpgo.VarBinds, len(tr.Oids))
	off := make([]int, len(tr.Oids))
	for i := range tr.Oids {
		off[i] = i
	}
	version := snmpgo.V2c
	if tr.SnmpV1 {
		version = snmpgo.V1
	}
	// This is kept only for SnmpV1 requests
	origMsg := NewMessageWithOids(version, snmpgo.GetNextRequest, tr.Community, tr.Oids)
	var onResp func(r MessageResponse)
	onResp = func(r MessageResponse) {
		next := make(snmpgo.Oids, 0, len(off))
		nextOff := make([]int, 0, len(off))
		if r.Err != nil {
			tr.send(ctx, nil, r.Err)
			return
		}

		pdu := r.Response.Pdu
		pvbs := pdu.VarBinds()

		if len(pvbs) != len(off) {
			tr.send(ctx, nil, &ErrMalformedResponse{
				ExpOIDs: len(off),
				GotOIDs: len(pvbs),
			})
			return
		}

		for i, vb := range pvbs {
			idx := off[i]

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

			if !vb.Oid.Contains(tr.Oids[idx]) {
				continue
			}
			next = append(next, vb.Oid)
			vbs[idx] = append(vbs[idx], vb)
			nextOff = append(nextOff, off[i])
		}
		off = nextOff

		if len(off) == 0 {
			tr.send(ctx, vbs, nil)
			return
		}

		mr := &MessageRequest{
			Addr:     tr.Addr,
			Message:  NewMessageWithOids(version, snmpgo.GetNextRequest, tr.Community, next),
			Response: onResp,
		}
		if tr.Retries != 0 && tr.TimeoutAfter != 0 {
			mr.Retries(tr.Retries, tr.TimeoutAfter)
		}
		select {
		case <-ctx.Done():
			tr.send(ctx, nil, ctx.Err())
		case ms.MC <- mr:
		}
	}

	mr := &MessageRequest{
		Addr:     tr.Addr,
		Message:  origMsg,
		Response: onResp,
	}
	if tr.Retries != 0 && tr.TimeoutAfter != 0 {
		mr.Retries(tr.Retries, tr.TimeoutAfter)
	}
	select {
	case <-ctx.Done():
		tr.send(ctx, nil, ctx.Err())
	case ms.MC <- mr:
	}
}

func (ms *MessageSender) tableChanNewFastMessage(tr *TableRequest) {
	ctx := tr.Context
	if ctx == nil {
		ctx = ms.ctx
	}
	vbs := make([]snmpgo.VarBinds, len(tr.Oids))
	off := make([]int, len(tr.Oids))
	last := make(snmpgo.Oids, len(tr.Oids))
	for i := range tr.Oids {
		off[i] = i
	}

	origMsg := NewMessageWithOids(snmpgo.V2c, snmpgo.GetBulkRequest, tr.Community, tr.Oids)
	origMsg.Pdu.SetMaxRepetitions(tr.MaxRep)
	var onResp func(r MessageResponse)

	// fmt.Println("=== Request started ===")
	onResp = func(r MessageResponse) {
		if r.Err != nil {
			tr.send(ctx, nil, r.Err)
			return
		}

		pdu := r.Response.Pdu
		pvbs := pdu.VarBinds()

		unhealthy := make([]bool, len(off))

		for i, vb := range pvbs {
			mI := i % len(off)
			idx := off[mI]
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

			if bad || !vb.Oid.Contains(tr.Oids[idx]) {
				// fmt.Printf("i=%d mI=%d idx=%d %s does not contain %s\n", i, mI, idx, vb.Oid, tr.Oids[idx])
				unhealthy[mI] = true
				continue
			}

			//idx := off[mI]
			last[idx] = vb.Oid
			vbs[idx] = append(vbs[idx], vb)
		}

		// malloc inefficient, will fix if it ever becomes an issue (it won't)
		next := make(snmpgo.Oids, 0, len(off))
		nextOff := make([]int, 0, len(off))
		for i, bad := range unhealthy {
			if !bad {
				idx := off[i]
				v := vbs[idx]
				next = append(next, v[len(v)-1].Oid)
				nextOff = append(nextOff, off[i])
			}
		}

		off = nextOff

		if len(off) == 0 {
			tr.send(ctx, vbs, nil)
			return
		}

		mr := &MessageRequest{
			Addr:     tr.Addr,
			Message:  NewMessageWithOids(snmpgo.V2c, snmpgo.GetBulkRequest, tr.Community, next),
			Response: onResp,
		}
		mr.Message.Pdu.SetMaxRepetitions(tr.MaxRep)

		if tr.Retries != 0 && tr.TimeoutAfter != 0 {
			mr.Retries(tr.Retries, tr.TimeoutAfter)
		}
		select {
		case <-ctx.Done():
			tr.send(ctx, nil, ctx.Err())
		case ms.MC <- mr:
		}
	}

	mr := &MessageRequest{
		Addr:     tr.Addr,
		Message:  origMsg,
		Response: onResp,
	}
	if tr.Retries != 0 && tr.TimeoutAfter != 0 {
		mr.Retries(tr.Retries, tr.TimeoutAfter)
	}
	select {
	case <-ctx.Done():
		tr.send(ctx, nil, ctx.Err())
	case ms.MC <- mr:
	}
}
