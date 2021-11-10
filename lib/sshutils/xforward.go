package sshutils

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/gravitational/trace"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

type x11Request struct {
	SingleConnection bool
	AuthProtocol     string
	AuthCookie       string
	ScreenNumber     uint32
}

type x11Response struct {
	InitialWindowSize uint32
	MaximumPacketSize uint32
	OriginatorAddress string
	OriginatorPort    uint32
}

func RequestX11Channel(sess *ssh.Session) error {
	// Generate a random 128-bit MIT-MAGIC-COOKIE-1
	cookieBytes := make([]byte, 32)
	if _, err := rand.Read(cookieBytes); err != nil {
		return trace.Wrap(err)
	}

	payload := x11Request{
		SingleConnection: false,
		AuthProtocol:     string("MIT-MAGIC-COOKIE-1"),
		AuthCookie:       string(hex.EncodeToString(cookieBytes)),
		ScreenNumber:     uint32(0),
	}

	ok, err := sess.SendRequest(X11ForwardRequest, true, ssh.Marshal(payload))
	if err != nil {
		return trace.Wrap(err)
	} else if !ok {
		return trace.BadParameter("x11 channel request failed")
	}

	return nil
}

func HandleX11Channel(clt *ssh.Client) error {
	xchs := clt.HandleChannelOpen(X11ChannelRequest)
	if xchs == nil {
		return trace.AlreadyExists("x11 forwarding channel already open")
	}
	go func() {
		for ch := range xchs {
			go handleX11ChannelRequest(ch)
		}
	}()
	return nil
}

// handleX11ChannelRequest accepts an X11 channel and forwards it back to the client.
// Servers which support X11 forwarding request a separate channel for serving each
// inbound connection on the X11 socket of the remote session.
func handleX11ChannelRequest(xreq ssh.NewChannel) {
	// accept inbound X11 channel from server
	sch, _, err := xreq.Accept()
	if err != nil {
		log.Errorf("x11 channel fwd failed: %v", err)
		return
	}
	defer sch.Close()

	// open a unix socket for the X11 display
	conn, err := dialX11Display(os.Getenv("DISPLAY"))
	if err != nil {
		log.Errorf("x11 channel fwd failed: %v", err)
		return
	}
	defer conn.Close()

	// setup wait group for io forwarding goroutines
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		// forward data from client to X11 unix socket
		io.Copy(conn, sch)
		// inform unix socket that no more data is coming
		conn.(*net.UnixConn).CloseWrite()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		// forward data from x11 unix socket to client
		io.Copy(sch, conn)
		// inform server that no more data is coming
		sch.CloseWrite()
	}()
	wg.Wait()
}

// dialX11Display dials the local x11 socket.
func dialX11Display(display string) (net.Conn, error) {
	xAddr := display
	if xAddr[0] != '/' {
		xAddr = fmt.Sprintf("/tmp/.X11-unix/X%v", parseDisplayNumber(display))
	}
	return net.Dial("unix", xAddr)
}

// Parse unix DISPLAY value e.g. [hostname]:[display].[screen_number]
func parseDisplayNumber(d string) string {
	colonIdx := strings.LastIndex(d, ":")
	if colonIdx < 0 {
		return "0"
	}

	dotIdx := strings.LastIndex(d, ".")
	if dotIdx < 0 || dotIdx <= colonIdx {
		dotIdx = len(d)
	}

	return d[colonIdx+1 : dotIdx]
}
