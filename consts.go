package snmp

import (
	"log"
	"time"
)

const (
	defaultRetry      = 2
	defaultRetryAfter = time.Second
	// DefaultChanSize represents the default queue size of MessageSender.MC and MessageSender.TC
	DefaultChanSize = 20
	// ErrTimedOut is emitted when the server did not respond in time
	ErrTimedOut = errTimedOut("Timed Out")
	// ErrWalkSingleOid is emitted when a snmpgo.GetBulkRequest PDU type with
	// MessageRequest.DontWant set to false requested, but 0 or more than one
	// OIDS were provided
	ErrWalkSingleOid = errWalkSingleOid("bulkwalk only supports a single OID")
	// DefaultErrorLogger (which implements ErrorLogger) is used when the error logger
	// passed into NewMessageSender and NewMessageSenderWithConn is nil. It is called
	// when an error occurs, namely the code is unable to marshal or unmarshal a
	// message, or a socket read error occurs), or a validation step failed, this
	// type is called with the error
	DefaultErrorLogger = defaultErrorLogger("I am the default error logger!")
)

type errTimedOut string

func (e errTimedOut) Error() string { return string(e) }

type errWalkSingleOid string

func (e errWalkSingleOid) Error() string { return string(e) }

// ErrorLogger is used when the error logger
// passed into NewMessageSender and NewMessageSenderWithConn is nil. It is called
// when an error occurs, namely the code is unable to marshal or unmarshal a
// message, or a socket read error occurs), or a validation step failed, this
// type is called with the error
type ErrorLogger interface {
	Log(err error)
}

type defaultErrorLogger string

func (l defaultErrorLogger) Log(err error) {
	log.Print(err.Error())
}
