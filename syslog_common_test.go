// +build !plan9

package syslog

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

var crashy = false

const caPem = `-----BEGIN CERTIFICATE-----
MIICXzCCAcqgAwIBAgIBADALBgkqhkiG9w0BAQUwRTENMAsGA1UEChMEanVqdTE0
MDIGA1UEAwwranVqdS1nZW5lcmF0ZWQgQ0EgZm9yIGVudmlyb25tZW50ICJyc3lz
bG9nIjAeFw0xNDA4MDUxMjEzNTBaFw0yNDA4MDUxMjE4NTBaMEUxDTALBgNVBAoT
BGp1anUxNDAyBgNVBAMMK2p1anUtZ2VuZXJhdGVkIENBIGZvciBlbnZpcm9ubWVu
dCAicnN5c2xvZyIwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBALSz4DWGHrXW
xp6uwwJ3j6amUhQajtGetkrPWLXp85gpdnwDgXgCOm/RXWHV2F2FtiSXkAf9FOQR
AOz2UhElHRMsv4+dsLJL9HfG2VtD6p73qR4vpwMYfIYb9ofHoK9A9tSpUoZRwZRz
wgoiayjeXvXMh9WRiszjln9dpYsUmZQlAgMBAAGjYzBhMA4GA1UdDwEB/wQEAwIA
pDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRtRlWT4zNaljsAYuaJo4epOwaH
HTAfBgNVHSMEGDAWgBRtRlWT4zNaljsAYuaJo4epOwaHHTALBgkqhkiG9w0BAQUD
gYEAAwi3/RUlgxt5xEQW3V4kgZmyAMrGt6uM417htZw/7E9CkfCFPjYKIITQKjAO
2ytOpL9dkJcDPW488vWkTBBqBSJWX6Vjz+T1Z6sebw24+VvvTo7oaQGhlJD4stLY
byTiSrVQmhaH5QPCErgdeBn6AZkIZ1XuB5VMoYTYbBLObO0=
-----END CERTIFICATE-----`

const cert = `-----BEGIN CERTIFICATE-----
MIICOTCCAaSgAwIBAgIBADALBgkqhkiG9w0BAQUwRTENMAsGA1UEChMEanVqdTE0
MDIGA1UEAwwranVqdS1nZW5lcmF0ZWQgQ0EgZm9yIGVudmlyb25tZW50ICJyc3lz
bG9nIjAeFw0xNDA4MDUxMjEzNTBaFw0yNDA4MDUxMjE4NTBaMBsxDTALBgNVBAoT
BGp1anUxCjAIBgNVBAMTASowgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAOBc
CBEBj2K6dcV3xm1vqByyhki8dUl4AxmnrVDwr7pNKvgyf3t0qoY6/8P+/fphge8M
yFNS0cDmIL27PvUxFOdsPLFDEBeuY373L8EerYMq3Gp/M/UW4k/lwZEuRTKQ4oZ1
mvjXySKEAqroQ8Fq7wOLRkBORLbBFJ47au9U4HKhAgMBAAGjZzBlMA4GA1UdDwEB
/wQEAwIAqDATBgNVHSUEDDAKBggrBgEFBQcDATAdBgNVHQ4EFgQU8RsHN12K62sV
irTv3dPEFrVjV0swHwYDVR0jBBgwFoAUbUZVk+MzWpY7AGLmiaOHqTsGhx0wCwYJ
KoZIhvcNAQEFA4GBAKdb7/YA3u7SuGxXMEoFz6zqe51E+CfNhhToNXEHFX2JYRUk
aDvUNHDelSsclipo8LEBwvffcN9PH3ruWVlNusGyLjMFaKcuhjJHwv+AoOHpJgBd
AFWciBspXneItQs1wi5kwyFPphLJifEOS83Sc4jtqHj5lq8vjoYBzDLgrnHw
-----END CERTIFICATE-----`

const key = `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDgXAgRAY9iunXFd8Ztb6gcsoZIvHVJeAMZp61Q8K+6TSr4Mn97
dKqGOv/D/v36YYHvDMhTUtHA5iC9uz71MRTnbDyxQxAXrmN+9y/BHq2DKtxqfzP1
FuJP5cGRLkUykOKGdZr418kihAKq6EPBau8Di0ZATkS2wRSeO2rvVOByoQIDAQAB
AoGAD/hdFqDOzQ9KvNCmzjlpdQl8J4dKrf0d82CNJLrNN2ywx1QI4QfP75gZhqEL
ARyZvCNjyxKVHa8D252NgLSKsUBTGllB3Dn9M8MZ9i9w6AapSwTwy9hxCrgB6ILC
6BnWW+HpuWq6v1Ft+lNycwoDwlevlpX7jfpmQTaNxYFg2jECQQDs354qlZs/Boqz
RTdgkM31kglcXUo8W4ZxU35DiVWsGb24boo6HurTwyqJBOogxDnWIZw4kgCbdRUW
FMA/04TtAkEA8nm8+WghdSgRDxXD486zzhrRnt6++vcARiJs4Mc621H9yjNwLrHz
2eIdWeE/2/xXtETWtGTX9ByQ8ufg3+kCBQJADDlF+kCaMFhwE+xAfVU7q66LmR6f
VBoNCBAc9fNCXo09gyUBMRqjV6Y8rbF5O5OkwG4fl7PBIEScf/U2LpUFyQJBAIdt
rzquCmHhKwX95hdKz+qB2CqfxpNted2yRJWXMSxmMxXIfRPXmJdNT49v27cGzgWF
nVXMLUHO4raJBHSLM/ECQQCAAuxb/GLAPDH9cbHo1BglU2mSzT81hSqanXcAapeh
2Y4xinXaXKxrgDFmPQJJZ2P+iCQuZp522N1+uro1zDlL
-----END RSA PRIVATE KEY-----`

func runPktSyslog(c net.PacketConn, done chan<- string) {
	var buf [4096]byte
	var rcvd string
	ct := 0
	for {
		var n int
		var err error

		c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, _, err = c.ReadFrom(buf[:])
		rcvd += string(buf[:n])
		if err != nil {
			if oe, ok := err.(*net.OpError); ok {
				if ct < 3 && oe.Temporary() {
					ct++
					continue
				}
			}
			break
		}
	}
	c.Close()
	done <- rcvd
}

func startServer(n, la string, done chan<- string, tlsCfg *tls.Config) (addr string, sock io.Closer, wg *sync.WaitGroup) {
	if n == "udp" || n == "tcp" {
		la = "127.0.0.1:0"
	} else {
		// unix and unixgram: choose an address if none given
		if la == "" {
			// use ioutil.TempFile to get a name that is unique
			f, err := ioutil.TempFile("", "syslogtest")
			if err != nil {
				log.Fatal("TempFile: ", err)
			}
			f.Close()
			la = f.Name()
		}
		os.Remove(la)
	}

	wg = new(sync.WaitGroup)
	if n == "udp" || n == "unixgram" {
		l, e := net.ListenPacket(n, la)
		if e != nil {
			log.Fatalf("startServer failed: %v", e)
		}
		addr = l.LocalAddr().String()
		sock = l
		wg.Add(1)
		go func() {
			defer wg.Done()
			runPktSyslog(l, done)
		}()
	} else {
		var l net.Listener
		var e error
		if tlsCfg != nil {
			l, e = tls.Listen(n, la, tlsCfg)
		} else {
			l, e = net.Listen(n, la)
		}
		if e != nil {
			log.Fatalf("startServer failed: %v", e)
		}
		addr = l.Addr().String()
		sock = l
		wg.Add(1)
		go func() {
			defer wg.Done()
			runStreamSyslog(l, done, wg)
		}()
	}
	return
}

func runStreamSyslog(l net.Listener, done chan<- string, wg *sync.WaitGroup) {
	for {
		var c net.Conn
		var err error
		if c, err = l.Accept(); err != nil {
			return
		}
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			c.SetReadDeadline(time.Now().Add(5 * time.Second))
			b := bufio.NewReader(c)
			for ct := 1; !crashy || ct&7 != 0; ct++ {
				s, err := b.ReadString('\n')
				if err != nil {
					break
				}
				done <- s
			}
			c.Close()
		}(c)
	}
}

func TestConcurrentWrite(t *testing.T) {
	addr, sock, srvWG := startServer("udp", "", make(chan string, 1), nil)
	defer srvWG.Wait()
	defer sock.Close()
	w, err := Dial("udp", addr, LOG_USER|LOG_ERR, "how's it going?", nil)
	if err != nil {
		t.Fatalf("syslog.Dial() failed: %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := w.Info("test")
			if err != nil {
				t.Errorf("Info() failed: %v", err)
				return
			}
		}()
	}
	wg.Wait()
}

func TestWithSimulated(t *testing.T) {
	msg := "Test 123"

	for _, tr := range transports {
		done := make(chan string)
		addr, sock, srvWG := startServer(tr, "", done, nil)
		defer srvWG.Wait()
		defer sock.Close()
		if tr == "unix" || tr == "unixgram" {
			defer os.Remove(addr)
		}
		s, err := Dial(tr, addr, LOG_INFO|LOG_USER, "syslog_test", nil)
		if err != nil {
			t.Fatalf("Dial() failed: %v", err)
		}
		err = s.Info(msg)
		if err != nil {
			t.Fatalf("log failed: %v", err)
		}
		check(t, msg, <-done)
		s.Close()
	}
}

func check(t *testing.T, in, out string) {
	tmpl := fmt.Sprintf("<%d>%%s %%s syslog_test[%%d]: %s\n", LOG_USER+LOG_INFO, in)
	if hostname, err := os.Hostname(); err != nil {
		t.Error("Error retrieving hostname")
	} else {
		var parsedHostname, timestamp string
		var pid int
		if n, err := fmt.Sscanf(out, tmpl, &timestamp, &parsedHostname, &pid); n != 3 || err != nil || hostname != parsedHostname {
			t.Errorf("Got %q, does not match template %q (%d %s)", out, tmpl, n, err)
		}
	}
}

func TestDial(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping syslog test during -short")
	}
	done := make(chan string)
	addr, sock, srvWG := startServer("tcp", "", done, nil)
	defer srvWG.Wait()
	defer sock.Close()
	f, err := Dial("tcp", addr, (LOG_LOCAL7|LOG_DEBUG)+1, "syslog_test", nil)
	if f != nil {
		t.Fatalf("Should have trapped bad priority")
	}
	f, err = Dial("tcp", addr, -1, "syslog_test", nil)
	if f != nil {
		t.Fatalf("Should have trapped bad priority")
	}
	l, err := Dial("tcp", addr, LOG_USER|LOG_ERR, "syslog_test", nil)
	if err != nil {
		t.Fatalf("Dial() failed: %s", err)
	}
	l.Close()
}

func TestTLSDial(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping syslog test during -short")
	}
	certificate, err := tls.X509KeyPair([]byte(cert), []byte(key))
	caCert := x509.NewCertPool()
	ok := caCert.AppendCertsFromPEM([]byte(caPem))
	if !ok {
		t.Fatalf("failed to parse root certificate")
	}

	srvCfg := &tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{certificate}, RootCAs: caCert}
	clientCfg := &tls.Config{ClientCAs: caCert, InsecureSkipVerify: true}

	done := make(chan string)
	addr, sock, srvWG := startServer("tcp", "", done, srvCfg)
	defer srvWG.Wait()
	defer sock.Close()
	f, err := Dial("tcp", addr, (LOG_LOCAL7|LOG_DEBUG)+1, "syslog_test", clientCfg)
	if f != nil {
		t.Fatalf("Should have trapped bad priority")
	}
	f, err = Dial("tcp", addr, -1, "syslog_test", clientCfg)
	if f != nil {
		t.Fatalf("Should have trapped bad priority")
	}
	l, err := Dial("tcp", addr, LOG_USER|LOG_ERR, "syslog_test", clientCfg)
	if err != nil {
		t.Fatalf("Dial() failed: %s", err)
	}
	l.Close()
}

func TestConcurrentReconnect(t *testing.T) {
	crashy = true
	defer func() { crashy = false }()

	const N = 10
	const M = 100
	net := "tcp"
	done := make(chan string, N*M)
	addr, sock, srvWG := startServer(net, "", done, nil)
	defer os.Remove(addr)

	// count all the messages arriving
	count := make(chan int)
	go func() {
		ct := 0
		for _ = range done {
			ct++
			// we are looking for 500 out of 1000 events
			// here because lots of log messages are lost
			// in buffers (kernel and/or bufio)
			if ct > N*M/2 {
				break
			}
		}
		count <- ct
	}()

	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			w, err := Dial(net, addr, LOG_USER|LOG_ERR, "tag", nil)
			if err != nil {
				t.Fatalf("syslog.Dial() failed: %v", err)
			}
			defer w.Close()
			for i := 0; i < M; i++ {
				err := w.Info("test")
				if err != nil {
					t.Errorf("Info() failed: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
	sock.Close()
	srvWG.Wait()
	close(done)

	select {
	case <-count:
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout in concurrent reconnect")
	}
}

func TestWrite(t *testing.T) {
	tests := []struct {
		pri Priority
		pre string
		msg string
		exp string
	}{
		{LOG_USER | LOG_ERR, "syslog_test", "", "%s %s syslog_test[%d]: \n"},
		{LOG_USER | LOG_ERR, "syslog_test", "write test", "%s %s syslog_test[%d]: write test\n"},
		// Write should not add \n if there already is one
		{LOG_USER | LOG_ERR, "syslog_test", "write test 2\n", "%s %s syslog_test[%d]: write test 2\n"},
	}

	if hostname, err := os.Hostname(); err != nil {
		t.Fatalf("Error retrieving hostname")
	} else {
		for _, test := range tests {
			done := make(chan string)
			addr, sock, srvWG := startServer("udp", "", done, nil)
			defer srvWG.Wait()
			defer sock.Close()
			l, err := Dial("udp", addr, test.pri, test.pre, nil)
			if err != nil {
				t.Fatalf("syslog.Dial() failed: %v", err)
			}
			defer l.Close()
			_, err = io.WriteString(l, test.msg)
			if err != nil {
				t.Fatalf("WriteString() failed: %v", err)
			}
			rcvd := <-done
			test.exp = fmt.Sprintf("<%d>", test.pri) + test.exp
			var parsedHostname, timestamp string
			var pid int
			if n, err := fmt.Sscanf(rcvd, test.exp, &timestamp, &parsedHostname, &pid); n != 3 || err != nil || hostname != parsedHostname {
				t.Errorf("s.Info() = '%q', didn't match '%q' (%d %s)", rcvd, test.exp, n, err)
			}
		}
	}
}

func TestFlap(t *testing.T) {
	net := "tcp"
	done := make(chan string)
	addr, sock, srvWG := startServer(net, "", done, nil)
	defer srvWG.Wait()
	defer sock.Close()

	s, err := Dial(net, addr, LOG_INFO|LOG_USER, "syslog_test", nil)
	if err != nil {
		t.Fatalf("Dial() failed: %v", err)
	}
	msg := "Moo 2"
	err = s.Info(msg)
	if err != nil {
		t.Fatalf("log failed: %v", err)
	}
	check(t, msg, <-done)

	// restart the server
	_, sock2, srvWG2 := startServer(net, addr, done, nil)
	defer srvWG2.Wait()
	defer sock2.Close()

	// and try retransmitting
	msg = "Moo 3"
	err = s.Info(msg)
	if err != nil {
		t.Fatalf("log failed: %v", err)
	}
	check(t, msg, <-done)

	s.Close()
}
