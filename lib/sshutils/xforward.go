package sshutils

import (
	"encoding/binary"
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
	display := os.Getenv("DISPLAY")
	displayNumber := parseDisplayNumber(display)

	// TODO: Compare cookie options more
	_, xAuth, err := readAuthority("", displayNumber)
	if err != io.EOF && err != nil {
		return trace.Wrap(err)
	}

	var cookie string
	for _, d := range xAuth {
		cookie = cookie + fmt.Sprintf("%02x", d)
	}

	payload := x11Request{
		SingleConnection: false,
		AuthProtocol:     string("MIT-MAGIC-COOKIE-1"),
		AuthCookie:       string(cookie),
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

// readAuthority Read env `$XAUTHORITY`. If not set value, read `~/.Xauthority`.
func readAuthority(hostname, display string) (
	name string, data []byte, err error) {

	// b is a scratch buffer to use and should be at least 256 bytes long
	// (i.e. it should be able to hold a hostname).
	b := make([]byte, 256)

	// As per /usr/include/X11/Xauth.h.
	const familyLocal = 256

	if len(hostname) == 0 || hostname == "localhost" {
		hostname, err = os.Hostname()
		if err != nil {
			return "", nil, err
		}
	}

	fname := os.Getenv("XAUTHORITY")
	if len(fname) == 0 {
		home := os.Getenv("HOME")
		if len(home) == 0 {
			err = trace.Errorf("Xauthority not found: $XAUTHORITY, $HOME not set")
			return "", nil, err
		}
		fname = home + "/.Xauthority"
	}

	r, err := os.Open(fname)
	if err != nil {
		return "", nil, err
	}
	defer r.Close()

	for {
		var family uint16
		if err := binary.Read(r, binary.BigEndian, &family); err != nil {
			return "", nil, err
		}

		addr, err := getString(r, b)
		if err != nil {
			return "", nil, err
		}

		disp, err := getString(r, b)
		if err != nil {
			return "", nil, err
		}

		name0, err := getString(r, b)
		if err != nil {
			return "", nil, err
		}

		data0, err := getBytes(r, b)
		if err != nil {
			return "", nil, err
		}

		if family == familyLocal && addr == hostname && disp == display {
			return name0, data0, nil
		}
	}
}

// getBytes use `readAuthority`
func getBytes(r io.Reader, b []byte) ([]byte, error) {
	var n uint16
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, err
	} else if n > uint16(len(b)) {
		return nil, trace.Errorf("bytes too long for buffer")
	}

	if _, err := io.ReadFull(r, b[0:n]); err != nil {
		return nil, err
	}
	return b[0:n], nil
}

// getString use `readAuthority`
func getString(r io.Reader, b []byte) (string, error) {
	b, err := getBytes(r, b)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
