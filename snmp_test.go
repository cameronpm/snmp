package snmp

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/k-sone/snmpgo"
	"github.com/stretchr/testify/require"
)

func TestStopViaContext(t *testing.T) {
	pse := envSetup()
	timer := time.AfterFunc(100*time.Millisecond, pse.cmain.cancel)
	defer pse.cmain.cancel()
	defer timer.Stop()

	t.Run("shutdown context", func(t *testing.T) {
		pse.cps.cancel()
		pse.stop(t, 200*time.Millisecond)
	})
}

func TestStopViaConn(t *testing.T) {
	pse := envSetup()
	timer := time.AfterFunc(100*time.Millisecond, pse.cmain.cancel)
	defer pse.cmain.cancel()
	defer timer.Stop()

	t.Run("shutdown conn", func(t *testing.T) {
		pse.conn.c.cancel()
		pse.stop(t, 200*time.Millisecond)
	})
}

func TestGetRetry(t *testing.T) {
	retriesTab := []struct {
		msg     string
		drops   int
		retries int
		after   time.Duration
		fail    bool
		err     error
	}{
		{msg: "simple case"},
		{msg: "single drop, no retry, force failure callback message", drops: 1, after: 50 * time.Millisecond, fail: true, err: ErrTimedOut},
		{msg: "single drop and retry", drops: 1, retries: 1, after: 50 * time.Millisecond},
		{msg: "multi drop and multi retry", drops: 2, retries: 3, after: 10 * time.Millisecond},
	}

	for _, r := range retriesTab {
		t.Run(r.msg, func(t *testing.T) {
			pse := envSetup()
			timer := time.AfterFunc(200*time.Millisecond, pse.cmain.cancel)

			//failFast := //context.WithDeadline()pse.cmain.ctx
			tc, tcCancel := context.WithTimeout(pse.cmain.ctx, 150*time.Millisecond)
			defer tcCancel() // shut up linter

			defer pse.cmain.cancel()
			defer timer.Stop()

			var oids snmpgo.Oids
			respC := make(chan MessageResponse)
			addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 161}

			t.Run("send get request", func(t *testing.T) {
				var err error
				sysDescr := "1.3.6.1.2.1.1.1.0"
				oids, err = snmpgo.NewOids([]string{sysDescr})
				require.NoError(t, err, "sysDescr oid [%s] parsed", sysDescr)

				msg := NewMessageWithOids(snmpgo.V2c, snmpgo.GetRequest, []byte("notpublic"), oids)
				mr := &MessageRequest{
					Addr:    addr,
					Message: msg,
					C:       respC,
				}
				if r.retries > 0 || r.after > 0 {
					mr.Retries(r.retries, r.after)
				}

				select {
				case pse.ps.MC <- mr:
				case <-time.After(50 * time.Millisecond):
					printstack()
					t.Fatal("timeout")
				case <-pse.cmain.ctx.Done():
					t.Fatal("parent timeout")
				}
			})

			var reqIDDrop, reqID int
			t.Run("get binary request", func(t *testing.T) {
				for i := 0; i < r.drops; i++ {
					select {
					case pkt := <-pse.conn.out:
						var msg Message
						_, err := msg.Unmarshal(pkt.p)
						require.NoError(t, err, "snmpget message parsed")
						require.Len(t, msg.Pdu.VarBinds(), 1, "pdu only has 1 oid")
						require.Equal(t, msg.Pdu.VarBinds()[0].Oid, oids[0], "oids are equal")
						if i > 0 {
							require.NotEqual(t, reqIDDrop, msg.Pdu.RequestId(), "new request ID allocated")
						}
						reqIDDrop = msg.Pdu.RequestId()
					case msg := <-pse.failMsg:
						t.Fatal(msg)
					case <-tc.Done():
						//printstack()
						t.Fatal("timeout")
					}
				}

				select {
				case pkt := <-pse.conn.out:
					var msg Message
					_, err := msg.Unmarshal(pkt.p)
					require.NoError(t, err, "snmpget message parsed")
					require.False(t, r.fail, "not in fail mode")
					require.Len(t, msg.Pdu.VarBinds(), 1, "pdu only has 1 oid")
					require.Equal(t, msg.Pdu.VarBinds()[0].Oid, oids[0], "oids are equal")
					if r.drops > 0 {
						require.NotEqual(t, reqIDDrop, reqID, "new request ID allocated")
					}
					reqID = msg.Pdu.RequestId()
					//case
				case msg := <-respC:
					require.True(t, r.fail, "must be in fail mode")
					require.Nil(t, msg.Response, "no response expected")
					require.Equal(t, r.err, msg.Err, "specific error type")

				case msg := <-pse.failMsg:
					t.Fatal(msg)
				case <-tc.Done():
					//printstack()
					t.Fatal("timeout")
				}
			})

			if r.fail {
				t.Log("By now the test has failed, don't proceed further")
				return
			}

			t.Run("send binary request", func(t *testing.T) {
				// sysDescr := "1.3.6.1.2.1.1.1.0"
				// oids, err = snmpgo.NewOids([]string{sysDescr})
				// require.NoError(t, err, "sysDescr oid [%s] parsed", sysDescr)
				vb := snmpgo.NewVarBind(oids[0], snmpgo.NewOctetString([]byte("my machine 1.0")))
				msg := NewMessageWithVarBinds(snmpgo.V2c, snmpgo.GetResponse, []byte("notpublic"), snmpgo.VarBinds{vb})
				msg.Pdu.SetRequestId(reqID)
				buf, err := msg.Marshal()
				require.NoError(t, err, "pdu marshal failed")

				select {
				case pse.conn.in <- packet{p: buf, addr: addr}:
				case msg := <-pse.failMsg:
					t.Fatal(msg)
				case <-tc.Done():
					//printstack()
					t.Fatal("timeout")
				}
			})

			t.Run("get response", func(t *testing.T) {
				select {
				case msg := <-respC:
					if r.fail {
						require.Nil(t, msg.Response, "Response is nil on fail")
						t.Fatalf("blah %T %v", msg.Err, msg.Err)
					} else {
						//t.Logf("%+v", &msg)
						//fmt.Println(fmt.Sprintf("%+v", &msg))
						// internal to SNMP so should not really check this
						// bulkwalk may return a different requestid legitimately
						require.Nil(t, msg.Err, "no error")
						require.NotNil(t, msg.Response, "msg response populated")
						require.NotNil(t, msg.Response.Pdu, "msg response populated")
						require.Equal(t, reqID, msg.Response.Pdu.RequestId())
					}
				case failMsg := <-pse.failMsg:
					t.Fatal(failMsg)
				case <-tc.Done():
					//printstack()
					t.Fatal("timeout")
				}
			})

			t.Run("shutdown context", func(t *testing.T) {
				pse.cps.cancel()
				pse.stop(t, 200*time.Millisecond)
			})
		})
	}
}

func pdu2string(pdu snmpgo.Pdu) string {
	var buf strings.Builder
	if pdu.PduType() == snmpgo.GetBulkRequest {
		buf.WriteString(fmt.Sprintf("[%d]", pdu.ErrorIndex()))
	}
	for _, vb := range pdu.VarBinds() {
		if buf.Len() > 0 {
			buf.WriteByte(' ')
		}
		buf.WriteString(vb.Oid.String())
	}

	return buf.String()
}

func TestBulkWalk(t *testing.T) {
	type expOidVal struct {
		oid string
		val int32
	}
	oid := func(k string) *snmpgo.Oid {
		oid, err := snmpgo.NewOid(k)
		require.NoError(t, err, "Error parsing %s", k)
		return oid
	}
	vb := func(k string, v uint32) *snmpgo.VarBind {
		return snmpgo.NewVarBind(oid(k), snmpgo.NewCounter32(v))
	}
	vbStr := func(k string, v string) *snmpgo.VarBind {
		return snmpgo.NewVarBind(oid(k), snmpgo.NewOctetString([]byte(v)))
	}
	vbV := func(k string, v snmpgo.Variable) *snmpgo.VarBind {
		return snmpgo.NewVarBind(oid(k), v)
	}
	type expOidResponse []expOidVal
	type expQueries map[string]snmpgo.VarBinds
	const (
		sysDescr      = "1.3.6.1.2.1.1.1"
		sysObjectID   = "1.3.6.1.2.1.1.2"
		ifInOctets    = "1.3.6.1.2.1.2.2.1.10"
		ifInUcastPkts = "1.3.6.1.2.1.2.2.1.11"
	)
	retriesTab := []struct {
		isV1       bool
		msg        string
		oids       []string
		slow       bool
		maxRep     int
		expErr     error
		expReply   []snmpgo.VarBinds
		expQueries expQueries
	}{
		//
		// SNMP v1 test block
		//
		{
			msg:  "snmpV1 all bad",
			isV1: true,
			oids: []string{ifInOctets},
			expReply: []snmpgo.VarBinds{
				snmpgo.VarBinds{},
			},
			expQueries: expQueries{
				ifInOctets: snmpgo.VarBinds{vbV(ifInOctets, snmpgo.NewNull())},
			},
		},
		{
			msg:  "snmpV1 mid bad",
			isV1: true,
			oids: []string{sysDescr, ifInOctets, ifInUcastPkts},
			expReply: []snmpgo.VarBinds{
				snmpgo.VarBinds{vbStr(sysDescr+".0", "hi")},
				snmpgo.VarBinds{},
				snmpgo.VarBinds{vb(ifInUcastPkts+".1", 6)},
			},
			expQueries: expQueries{
				sysDescr + " " + ifInOctets + " " + ifInUcastPkts: snmpgo.VarBinds{
					vbStr(sysDescr+".0", "ignored"),
					vbV(ifInOctets, snmpgo.NewNull()),
					vb(ifInUcastPkts+".1", 6),
				},
				sysDescr + " " + ifInUcastPkts: snmpgo.VarBinds{
					vbStr(sysDescr+".0", "hi"),
					vb(ifInUcastPkts+".1", 6),
				},
				sysDescr + ".0 " + ifInUcastPkts + ".1": snmpgo.VarBinds{
					vb(ifInUcastPkts+".0", 6),
					vbV(ifInUcastPkts+".1", snmpgo.NewNull()),
				},
				sysDescr + ".0": snmpgo.VarBinds{
					vb(ifInUcastPkts+".0", 6),
				},
			},
		},

		//
		// SNMP v2c snmpwalk test block
		//
		{
			msg:  "simple case",
			slow: true,
			oids: []string{ifInOctets},
			expReply: []snmpgo.VarBinds{
				snmpgo.VarBinds{
					vb(ifInOctets+".1", 3),
					vb(ifInOctets+".2", 4),
					vb(ifInOctets+".3", 5),
				},
			},
			expQueries: expQueries{
				ifInOctets:        snmpgo.VarBinds{vb(ifInOctets+".1", 3)},
				ifInOctets + ".1": snmpgo.VarBinds{vb(ifInOctets+".2", 4)},
				ifInOctets + ".2": snmpgo.VarBinds{vb(ifInOctets+".3", 5)},
				ifInOctets + ".3": snmpgo.VarBinds{vb(ifInUcastPkts+".1", 6)},
			},
		},
		{
			msg:  "multi OID",
			slow: true,
			oids: []string{sysDescr, ifInOctets},
			expReply: []snmpgo.VarBinds{
				snmpgo.VarBinds{vbStr(sysDescr+".0", "a boring machine desc")},
				snmpgo.VarBinds{
					vb(ifInOctets+".1", 3),
					vb(ifInOctets+".2", 4),
					vb(ifInOctets+".3", 5),
				},
			},
			expQueries: expQueries{
				sysDescr + " " + ifInOctets: snmpgo.VarBinds{
					vbStr(sysDescr+".0", "a boring machine desc"),
					vb(ifInOctets+".1", 3),
				},
				sysDescr + ".0 " + ifInOctets + ".1": snmpgo.VarBinds{
					vbStr(sysObjectID+".0", "should be an OID value type but im lazy :)"),
					vb(ifInOctets+".2", 4),
				},
				ifInOctets + ".2": snmpgo.VarBinds{vb(ifInOctets+".3", 5)},
				ifInOctets + ".3": snmpgo.VarBinds{vb(ifInUcastPkts+".1", 6)},
			},
		},
		{
			msg:  "end of mib",
			slow: true,
			oids: []string{ifInOctets},
			expReply: []snmpgo.VarBinds{
				snmpgo.VarBinds{
					vb(ifInOctets+".1", 3),
					vb(ifInOctets+".2", 4),
					vb(ifInOctets+".3", 5),
				},
			},
			expQueries: expQueries{
				ifInOctets:        snmpgo.VarBinds{vb(ifInOctets+".1", 3)},
				ifInOctets + ".1": snmpgo.VarBinds{vb(ifInOctets+".2", 4)},
				ifInOctets + ".2": snmpgo.VarBinds{vb(ifInOctets+".3", 5)},
				ifInOctets + ".3": snmpgo.VarBinds{vbV(ifInOctets+".3", snmpgo.NewEndOfMibView())},
			},
		},
		{
			msg:  "unimplemented table",
			slow: true,
			oids: []string{ifInOctets},
			expReply: []snmpgo.VarBinds{
				snmpgo.VarBinds{},
			},
			expQueries: expQueries{
				ifInOctets: snmpgo.VarBinds{vbV(ifInOctets, snmpgo.NewNoSucheObject())},
			},
		},

		//
		// SNMP v2c snmpwalk test block
		//
		{
			msg:    "bulk simple case",
			maxRep: 2,
			oids:   []string{ifInOctets},
			expReply: []snmpgo.VarBinds{
				snmpgo.VarBinds{
					vb(ifInOctets+".1", 3),
					vb(ifInOctets+".2", 4),
					vb(ifInOctets+".3", 5),
				},
			},
			expQueries: expQueries{
				"[2] " + ifInOctets: snmpgo.VarBinds{
					vb(ifInOctets+".1", 3),
					vb(ifInOctets+".2", 4),
				},
				"[2] " + ifInOctets + ".2": snmpgo.VarBinds{
					vb(ifInOctets+".3", 5),
					vb(ifInUcastPkts+".1", 6),
				},
			},
		},

		{
			msg:    "bulk multi OID",
			maxRep: 2,
			oids:   []string{sysDescr, ifInOctets},
			expReply: []snmpgo.VarBinds{
				snmpgo.VarBinds{vbStr(sysDescr+".0", "a boring machine desc")},
				snmpgo.VarBinds{
					vb(ifInOctets+".1", 3),
					vb(ifInOctets+".2", 4),
					vb(ifInOctets+".3", 5),
				},
			},
			expQueries: expQueries{
				"[2] " + sysDescr + " " + ifInOctets: snmpgo.VarBinds{
					vbStr(sysDescr+".0", "a boring machine desc"),
					vb(ifInOctets+".1", 3),
					vbV(sysObjectID+".0", snmpgo.MustNewOid("1.3.6.1.1.1.1")),
					vb(ifInOctets+".2", 4),
				},
				"[2] " + ifInOctets + ".2": snmpgo.VarBinds{
					vb(ifInOctets+".3", 5),
					vb(ifInUcastPkts+".1", 6),
				},
			},
		},

		{
			msg:    "bulk end of mib",
			maxRep: 2,
			oids:   []string{ifInOctets},
			expReply: []snmpgo.VarBinds{
				snmpgo.VarBinds{
					vb(ifInOctets+".1", 3),
					vb(ifInOctets+".2", 4),
					vb(ifInOctets+".3", 5),
				},
			},
			expQueries: expQueries{
				"[2] " + ifInOctets: snmpgo.VarBinds{
					vb(ifInOctets+".1", 3),
					vb(ifInOctets+".2", 4),
				},
				"[2] " + ifInOctets + ".2": snmpgo.VarBinds{
					vb(ifInOctets+".3", 5),
					vbV(ifInOctets+".3", snmpgo.NewEndOfMibView()),
				},
			},
		},

		{
			msg:    "unimplemented table",
			maxRep: 2,
			oids:   []string{ifInOctets},
			expReply: []snmpgo.VarBinds{
				snmpgo.VarBinds{},
			},
			expQueries: expQueries{
				"[2] " + ifInOctets: snmpgo.VarBinds{vbV(ifInOctets, snmpgo.NewNoSucheObject())},
			},
		},
	}

	for _, r := range retriesTab {
		lookup := r.expQueries
		t.Run(r.msg, func(t *testing.T) {
			pse := envSetup()
			timer := time.AfterFunc(200*time.Millisecond, pse.cmain.cancel)

			//failFast := //context.WithDeadline()pse.cmain.ctx
			tc, tcCancel := context.WithTimeout(pse.cmain.ctx, 150*time.Millisecond)
			defer tcCancel() // shut up linter

			defer pse.cmain.cancel()
			defer timer.Stop()

			var oids snmpgo.Oids
			addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 161}

			t.Run("parallel", func(t *testing.T) {
				successCtx, successOk := context.WithCancel(tc)

				t.Run("send table request, get response", func(t *testing.T) {
					t.Parallel()

					defer successOk()

					var err error
					oids, err = snmpgo.NewOids(r.oids)
					require.NoError(t, err, "ifInOctets oid [%s] parsed", ifInOctets)

					tr := &TableRequest{
						Addr:         addr,
						SnmpV1:       r.isV1,
						Oids:         oids,
						Community:    []byte("notpublic"),
						C:            make(chan TableResponse, 1),
						Retries:      2,
						TimeoutAfter: 10 * time.Millisecond,
						Slow:         r.slow,
						MaxRep:       r.maxRep,
					}
					pse.ps.TC <- tr

					select {
					case msg := <-tr.C:
						if r.expErr == nil {
							require.NoError(t, msg.Err, "unexpected error of type %T", msg.Err)
							require.Len(t, msg.VarBinds, len(r.expReply), "varbinds")
							for i, vbs := range r.expReply {
								vbsGot := msg.VarBinds[i]
								require.Len(t, vbsGot, len(vbs), "varbind %s", r.oids[i])
								for o, vb := range vbs {
									vbGot := vbsGot[o]
									require.True(t, vbGot.Oid.Equal(vb.Oid),
										"oid: got %s = exp %s", vbGot.Oid, vb.Oid)
									require.Equal(t, vbGot.Variable.String(), vb.Variable.String(),
										"val: got %s = exp %s", vbGot.Variable, vb.Variable)
								}
							}
						} else {
							require.Error(t, msg.Err, "yeah TODO")
						}
					case failMsg := <-pse.failMsg:
						t.Fatal(failMsg)
					case <-tc.Done():
						//printstack()
						t.Fatal("timeout")
					}
					successOk()
				})

				t.Run("respond table requests", func(t *testing.T) {
					t.Parallel()
					for {
						select {
						case pkt := <-pse.conn.out:
							// Marshal parsed bytes to a Message
							msg := &Message{}
							_, err := msg.Unmarshal(pkt.p)
							require.NoError(t, err, "snmpget message parsed")

							// Convert the messsage to a key form we can lookup the
							// expected response from
							wot := pdu2string(msg.Pdu)
							t.Logf("Got request %s\n", wot)
							if _, ok := lookup[wot]; !ok {
								t.Fatal("unhandled inbound request: " + wot)
							}

							// Construct and marshal the response
							msg2 := NewMessageWithVarBinds(snmpgo.V2c, snmpgo.GetResponse, []byte("notpublic"), lookup[wot])
							msg2.Pdu.SetRequestId(msg.Pdu.RequestId())
							if r.isV1 {
								// fake the V1 index badness check
								for i, vb := range lookup[wot] {
									if _, ok := vb.Variable.(*snmpgo.Null); ok {
										msg2.Pdu.SetErrorStatus(snmpgo.NoSuchName)
										msg2.Pdu.SetErrorIndex(i)
										break
									}
								}
							}
							buf, err := msg2.Marshal()
							require.NoError(t, err, "pdu marshal failed")

							t.Logf("Respond to '%s'", wot)

							// Send the response off
							select {
							case pse.conn.in <- packet{p: buf, addr: addr}:
								// success, loop for next response
							case failMsg := <-pse.failMsg:
								t.Fatal(failMsg)
							case <-successCtx.Done():
								t.Fatal("timeout sending response packet over channel")
							}

						case <-successCtx.Done():
							return

						case msg := <-pse.failMsg:
							t.Fatal(msg)

						case <-tc.Done():
							//printstack()
							t.Fatal("timeout")
						}
					}
				})
			})

			t.Run("shutdown context", func(t *testing.T) {
				pse.cps.cancel()
				pse.stop(t, 200*time.Millisecond)
			})
		})
	}
}

func TestCounter64(t *testing.T) {
	buf := []byte{
		0x30, 0x2f, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69,
		0x63, 0xa2, 0x22, 0x02, 0x04, 0x0b, 0x58, 0xf1, 0x52, 0x02, 0x01, 0x00,
		0x02, 0x01, 0x00, 0x30, 0x14, 0x30, 0x12, 0x06, 0x0b, 0x2b, 0x06, 0x01,
		0x02, 0x01, 0x1f, 0x01, 0x01, 0x01, 0x0a, 0x01, 0x46, 0x03, 0x17, 0x50,
		0x87,
	}
	var (
		err error
		got Message
		oid *snmpgo.Oid
	)
	_, err = got.Unmarshal(buf)
	require.NoError(t, err)
	oid, err = snmpgo.NewOid("1.3.6.1.2.1.31.1.1.1.10.1")
	require.NoError(t, err)
	exp := Message{
		Version:   snmpgo.V2c,
		Community: []byte("public"),
		Pdu:       snmpgo.NewPduWithVarBinds(snmpgo.V2c, snmpgo.GetResponse, snmpgo.VarBinds{snmpgo.NewVarBind(oid, snmpgo.NewCounter64(1527943))}),
	}
	exp.Pdu.SetRequestId(190378322)
	require.Equal(t, &exp, &got)
}

// throwaway, just wanted to know
func BenchmarkSimple(b *testing.B) {
	sysDescr := "1.3.6.1.2.1.1.1.0"
	val := []byte("my machine 1.0")
	for i := 0; i < b.N; i++ {
		oids, _ := snmpgo.NewOids([]string{sysDescr})
		vb := snmpgo.NewVarBind(oids[0], snmpgo.NewOctetString(val))
		_ = NewMessageWithVarBinds(snmpgo.V2c, snmpgo.GetResponse, []byte("notpublic"), snmpgo.VarBinds{vb})
	}
}

