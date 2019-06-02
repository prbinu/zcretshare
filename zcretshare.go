/*
   Copyright (c) 2019, NVIDIA CORPORATION. All rights reserved.
   Copyrights licensed under the BSD 3-Clause License. See the
   accompanying LICENSE.txt file for terms.
*/
package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/ScaleFT/sshkeys"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/crypto/ssh/terminal"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const defaultDir string = ".zcretshare"

var versionNumber, releaseDate string
var stdout io.Writer = os.Stdout

func getPeerPubKey(pubkeyLoc, cacertFile string) ([]byte, error) {

	if strings.HasPrefix(pubkeyLoc, "https://") {
		fmt.Fprintf(stdout, "Fetching public key from: %s\n", pubkeyLoc)

		var certPool *x509.CertPool = nil
		if len(cacertFile) != 0 {
			cacert, err := ioutil.ReadFile(cacertFile)
			if err != nil {
				log.Fatal(err)
			}

			certPool := x509.NewCertPool()
			certPool.AppendCertsFromPEM(cacert)
		}

		tls := &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: certPool},
		}

		timeout := time.Duration(10 * time.Second)
		client := &http.Client{Transport: tls, Timeout: timeout}

		res, err := client.Get(pubkeyLoc)
		if err != nil {
			return nil, err
		}

		buf, err := ioutil.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			return nil, err
		}

		return buf, nil
	}

	buf, err := ioutil.ReadFile(pubkeyLoc)
	if err != nil {
		return nil, err
	}

	return buf, nil
}

func recvSecret(conn *ssh.Client, file string) string {

	_, p, err := conn.SendRequest("ready", true, []byte(""))
	if err != nil {
		log.Fatal("error: failed to send secret, err:" + err.Error())
	}

	return fmt.Sprintf("%s", p)
}

func readSecret(file string) []byte {

	fd := os.Stdin
	var fname string

	if file != "-" {
		var err error

		fd, err = os.Open(file)
		if err != nil {
			log.Fatal(err)
		}

		fname = file + "\n"
	} else {
		fmt.Fprintf(stdout, "Reading from stdin..\n")
		fname = "stdin.out\n"
	}

	defer fd.Close()
	buf := bytes.NewBuffer([]byte(""))
	buf.ReadFrom(fd)

	content := append([]byte(fname), buf.Bytes()...)
	sha256 := sha256.Sum256(buf.Bytes())
	fmt.Fprintf(stdout, "Content fingerprint: SHA256:%v\n", base64.StdEncoding.EncodeToString([]byte(sha256[:])))

	return content
}

func saveSecret(payload []byte, outDir string, overwrite bool, stdout bool) error {

	// split payload into filename and file content
	pl := bytes.SplitN(payload, []byte("\n"), 2)
	// error check
	_, file := filepath.Split(string(pl[0]))

	// check if the filename is valid
	if len(file) == 0 {
		return fmt.Errorf("empty/invalid secret filename")
	}

	sha256 := sha256.Sum256(pl[1])
	if stdout {
		fmt.Fprintf(os.Stdout, "%s", pl[1])
		fmt.Fprintf(os.Stderr, "Content fingerprint: SHA256:%v\n", base64.StdEncoding.EncodeToString([]byte(sha256[:])))
		return nil
	}

	if strings.HasSuffix(outDir, defaultDir) {
		if _, err := os.Stat(outDir); os.IsNotExist(err) {
			os.Mkdir(outDir, 0700)
		}
	}

	file = filepath.Join(outDir, file)
	if !overwrite {
		if _, err := os.Stat(file); !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "file already exists: %s\nskipping save; remove/rename the file and retry or use -overwrite option\n", file)
			return err
		}
	}

	err := ioutil.WriteFile(file, pl[1], 0600)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Secret content saved to: %s\n", file)
	fmt.Fprintf(os.Stderr, "Content fingerprint: SHA256:%v\n", base64.StdEncoding.EncodeToString([]byte(sha256[:])))
	return nil
}

func getPrivateKeySigner(file string) (ssh.Signer, error) {

	buffer, err := ioutil.ReadFile(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot read SSH public key file: %s\n", file)
		return nil, err
	}

	block, _ := pem.Decode(buffer)
	if block == nil {
		return nil, fmt.Errorf("ssh: no key found")
	}

	var passwd bool = false
	if (block.Type == "ENCRYPTED PRIVATE KEY") || (strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED")) {
		passwd = true
	} else if block.Type == "OPENSSH PRIVATE KEY" {
		signer, err := sshkeys.ParseEncryptedPrivateKey(buffer, nil)
		if err != nil {
			passwd = true
			fmt.Fprintf(os.Stderr, "warning: OPENSSH PRIVATE KEY seems like encrypted..\n")
		} else {
			return signer, nil
		}
	}

	if passwd {
		fmt.Printf("Enter passphrase to decrypt ('%s'): ", file)
		passwd, err := terminal.ReadPassword(int(syscall.Stdin))

		if err != nil {
			fmt.Fprintf(os.Stderr, "error: failed to read passphrase, err: %v\n", err)
			return nil, err
		}

		return sshkeys.ParseEncryptedPrivateKey(buffer, passwd)
	}

	return ssh.ParsePrivateKey(buffer)
}

func proxyConnect(proxy, proxyKnownHostFile string, authMeth []ssh.AuthMethod) (*ssh.Client, error) {

	u, err := url.Parse(proxy)
	if err != nil {
		return nil, err
	}

	if len(u.User.Username()) == 0 {
		return nil, fmt.Errorf("ssh: missing proxy user name")
	}

	sshAddr := u.Host
	if len(u.Port()) == 0 {
		sshAddr = u.Hostname() + ":22"
	}

	hkc, err := knownhosts.New(proxyKnownHostFile)
	if err != nil {
		return nil, err
	}

	cfg := ssh.ClientConfig{
		User:            u.User.Username(),
		Auth:            authMeth,
		Timeout:         10 * time.Second,
		HostKeyCallback: hkc,
	}

	return ssh.Dial("tcp", sshAddr, &cfg)
}

func tildeExpand(path string) string {

	if !strings.HasPrefix(path, "~") {
		return path
	}

	exp := ""
	if runtime.GOOS == "windows" {
		usr, err := user.Current()
		if err != nil {
			log.Fatal(err)
		}
		exp = usr.HomeDir + "\\" + path[1:]
	} else {
		exp = os.Getenv("HOME") + path[1:]
	}
	return exp
}

func sshAuthMethods(keyFile string) ([]ssh.AuthMethod, error) {

	var authMeth []ssh.AuthMethod
	if len(keyFile) > 0 {

		key, err := getPrivateKeySigner(keyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\nwarning: private key (%s) parse failed, err: %v\n", keyFile, err)
		} else {
			authMeth = append(authMeth, ssh.PublicKeys(key))
		}

	} else {
		fmt.Fprintf(os.Stderr, "warning: no valid key file name; fallback to ssh-agent..\n")
	}

	if sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		authMeth = append(authMeth, ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers))
	} else {
		fmt.Fprintf(os.Stderr, "warning: ssh-agent (%s) connect failed, err: %v\n", os.Getenv("SSH_AUTH_SOCK"), err)
	}

	if len(authMeth) == 0 {
		return nil, fmt.Errorf("no ssh-agent/valid key found. configure ssh-agent (and export SSH_AUTH_SOCK) or use -key option")
	}

	return authMeth, nil
}

type cmdOptions struct {
	cmd                string
	connect            string
	listen             string
	keyFile            string
	proxy              string
	proxyKeyFile       string
	proxyKnownHostFile string
	peerKeyFile        string
	rfPort             string
	cacert             string
	overwrite          bool
	outputDir          string
	stdout             bool
	forever            bool
	quiet              bool
	infile             string
}

func buildAuthorizedKeysMap(opt cmdOptions) (map[string]bool, error) {

	authorizedKeysBytes, err := getPeerPubKey(opt.peerKeyFile, opt.cacert)
	if err != nil {
		return nil, fmt.Errorf("failed to load authorized_keys, err: %v\n", err)
	}

	if opt.cmd == "send" {
		fmt.Fprintf(os.Stderr, "Authorized receiver(s) key fingerprint (from %s):\n", opt.peerKeyFile)
	} else {
		fmt.Fprintf(os.Stderr, "Authorized sender(s) key fingerprint (from %s):\n", opt.peerKeyFile)
	}

	authorizedKeysMap := map[string]bool{}
	for len(authorizedKeysBytes) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
		if err != nil {
			return nil, fmt.Errorf("authorized key (%s) parse failed, err: %v\n", opt.peerKeyFile, err)
		}

		authorizedKeysMap[string(pubKey.Marshal())] = true
		authorizedKeysBytes = rest
		fmt.Fprintf(os.Stderr, "  %v\n", ssh.FingerprintSHA256(pubKey))
	}

	fmt.Fprintf(os.Stderr, "\n")
	return authorizedKeysMap, nil
}

func connect(opt cmdOptions) {

	fmt.Fprintln(stdout, "  /\\_/\\ ")
	fmt.Fprintln(stdout, " ( o.o )  SECRET SHARE PROGRAM")
	fmt.Fprintln(stdout, "  > ^ <   --------------------")

	var conn net.Conn
	var proxy *ssh.Client
	remoteAddr := "127.0.0.1:" + opt.rfPort

	if len(opt.proxy) > 0 {
		opt.connect = "127.0.0.1:" + opt.rfPort

		proxyAuthMeth, err := sshAuthMethods(opt.proxyKeyFile)
		if err != nil {
			log.Fatalf("error: proxy authentication methods, err: %v\n", err)
		}

		proxy, err = proxyConnect(opt.proxy, opt.proxyKnownHostFile, proxyAuthMeth)
		if err != nil {
			log.Fatalf("error: proxy SSH connect failed, err: %v\n", err)
		}

		defer proxy.Close()
		fmt.Fprintf(stdout, "Connected to proxy: %s\n", opt.proxy)

		conn, err = proxy.Dial("tcp", opt.connect)
		if err != nil {
			log.Fatalf("error: failed to connect target host (%s), error: %v\n",
				opt.connect, err)
		}

	} else {
		u, err := url.Parse(opt.connect)
		if err != nil {
			log.Fatalf("error: URL parse failed: %s, err: %v\n", opt.connect, err)
		}

		sshAddr := u.Host
		if len(u.Port()) == 0 {
			sshAddr = u.Hostname() + ":22"
		}

		conn, err = net.Dial("tcp", sshAddr)
		if err != nil {
			log.Fatalf("error: failed to connect target host (%s), error: %v\n",
				sshAddr, err)
		}

		remoteAddr = sshAddr
	}

	// TODO List
	// cert support (future)

	defer conn.Close()

	authorizedKeysMap, err := buildAuthorizedKeysMap(opt)
	if err != nil {
		log.Fatalf("error: %v\n", err)
	}

	authMeth, err := sshAuthMethods(opt.keyFile)
	if err != nil {
		log.Fatalf("error: authentication methods, err: %v\n", err)
	}

	hkc := func(hostname string, remote net.Addr, pubKey ssh.PublicKey) error {

		if !authorizedKeysMap[string(pubKey.Marshal())] {
			return fmt.Errorf("peer key mismatch. peer fingerprint: %v\n", ssh.FingerprintSHA256(pubKey))
		}

		fmt.Fprintf(stdout, "Connecting..\n")
		fmt.Fprintf(stdout, "Matched peer key fingerprint:\n  %v\n", ssh.FingerprintSHA256(pubKey))
		return nil
	}

	cfg := ssh.ClientConfig{
		User:            "zcretshare-user",
		Auth:            authMeth,
		Timeout:         10 * time.Second,
		HostKeyCallback: hkc,
	}

	c, chans, reqs, err := ssh.NewClientConn(conn, remoteAddr, &cfg)
	if err != nil {
		log.Fatalf("\nerror: sender connect failed, err: %v\n", err)
	} else {
		fmt.Fprintf(stdout, "Connected to: %v, ", remoteAddr)
		if opt.cmd == "send" {
			fmt.Fprintf(stdout, "sharing secret ")
			if opt.infile != "-" {
				fmt.Fprintf(stdout, "file: %s\n", opt.infile)
			} else {
				fmt.Fprintf(stdout, "from stdin..\n")
			}
		} else {
			fmt.Fprintf(stdout, "waiting for the secret to arrive..\n")
		}
	}

	results := make(chan []byte, 10)
	timeout := time.After(10 * time.Second)
	client := ssh.NewClient(c, chans, reqs)
	//	results <- sendSecret(client, opt.infile)

	var p []byte
	if opt.cmd == "send" {
		content := readSecret(opt.infile)
		_, p, err = client.SendRequest("copy", true, content)
	} else {
		_, p, err = client.SendRequest("ready", true, []byte(""))
	}

	if err != nil {
		log.Fatal("error: failed to send secret, err:" + err.Error())
	}

	results <- p

	select {
	case res := <-results:
		if opt.cmd == "send" {
			fmt.Fprintf(stdout, "%s\n", res)
		} else {
			err = saveSecret(res, opt.outputDir, opt.overwrite, opt.stdout)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to process sender request, err: %v\n", err)
			} //else {
			//req.Reply(true, []byte("Transfer complete!\n"))
			//}
		}
	case <-timeout:
		fmt.Fprintf(os.Stderr, "Timed out, exiting..")
		return
	}
}

func listen(opt cmdOptions) {

	fmt.Fprintln(stdout, "  /\\_/\\ ")
	fmt.Fprintln(stdout, " ( o.o )  SECRET SHARE PROGRAM")
	fmt.Fprintln(stdout, "  > ^ <   --------------------")

	var listener net.Listener
	var proxy *ssh.Client
	if len(opt.proxy) > 0 {
		opt.listen = "127.0.0.1:" + opt.rfPort

		proxyAuthMeth, err := sshAuthMethods(opt.proxyKeyFile)
		if err != nil {
			log.Fatalf("error: authentication methods, err: %v\n", err)
		}

		proxy, err = proxyConnect(opt.proxy, opt.proxyKnownHostFile,
			proxyAuthMeth)
		if err != nil {
			log.Fatalf("error: proxy SSH connect failed, err: %v\n", err)
		}
		defer proxy.Close()
		fmt.Fprintf(os.Stderr, "Connected to proxy: %s\n", opt.proxy)

		listener, err = proxy.Listen("tcp", opt.listen)
		if err != nil {
			log.Fatalf("error: proxy (%s) listen failed, err: %v\n",
				opt.listen, err)
		}

	} else {
		var err error
		listener, err = net.Listen("tcp", opt.listen)
		if err != nil {
			log.Fatalf("error: listen failed (%s), err: %v\n",
				opt.listen, err)
		}
	}

	defer listener.Close()
	authorizedKeysMap, err := buildAuthorizedKeysMap(opt)
	if err != nil {
		log.Fatalf("error: %v\n", err)
	}

	pkc := func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
		fmt.Fprintf(os.Stderr, "\nNew connection from: sender-addr: %v\t Time: %v\n", c.RemoteAddr(), time.Now().Local())

		if authorizedKeysMap[string(pubKey.Marshal())] {
			fmt.Fprintf(stdout, "Matched peer key fingerprint:\n  %v\n", ssh.FingerprintSHA256(pubKey))
			return &ssh.Permissions{
				// public key used for authentication.
				Extensions: map[string]string{
					"pubkey-fp": ssh.FingerprintSHA256(pubKey),
				},
			}, nil
		}

		return nil, fmt.Errorf("peer key mismatch. peer fingerprint: %v\n", ssh.FingerprintSHA256(pubKey))
	}

	config := &ssh.ServerConfig{
		NoClientAuth:      false,
		MaxAuthTries:      3,
		PublicKeyCallback: pkc,
	}

	key, err := getPrivateKeySigner(opt.keyFile)
	if err != nil {
		log.Fatalf("\nerror: private key (%s) parse failed, err: %v\n", opt.keyFile, err)
	}

	config.AddHostKey(key)

	acceptTimeout := false
	if !opt.forever {
		tout := make(chan bool, 1)
		go func() {
			time.Sleep(300 * time.Second)
			tout <- true
		}()

		go func() {
			select {
			case <-tout:
				fmt.Fprintf(os.Stderr, "warning: idle timeout, closing the session..")
				acceptTimeout = true
				listener.Close()
			}
		}()
	}

	fmt.Fprintf(os.Stderr, "Listening on %s\n", opt.listen)
	for {
		func() {
			tcpConn, err := listener.Accept()
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to accept incoming connection, err: %v\n", err)
				return
			}

			defer tcpConn.Close()
			timeout := make(chan bool, 1)
			go func() {
				time.Sleep(10 * time.Second)
				timeout <- true
			}()

			_, _, reqs, err := ssh.NewServerConn(tcpConn, config)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: SSH handshake failed, err: %v\n", err)
				return
			} else {
				fmt.Fprintf(stdout, "Connection accepted, ")
				if opt.cmd == "send" {
					fmt.Fprintf(stdout, "sharing secret ")
					if opt.infile != "-" {
						fmt.Fprintf(stdout, "file: %s\n", opt.infile)
					} else {
						fmt.Fprintf(stdout, "from stdin..\n")
					}
				} else {
					fmt.Fprintf(stdout, "waiting for the secret to arrive..\n")
				}
			}

			select {
			case req := <-reqs:
				if req == nil {
					fmt.Fprintf(os.Stderr, "warning: request read failed, closing the session..\n")
					return
				}

				switch req.Type {
				case "copy":

					err = saveSecret(req.Payload, opt.outputDir, opt.overwrite, opt.stdout)
					if err != nil {
						fmt.Fprintf(os.Stderr, "warning: failed to process sender request, err: %v\n", err)
					} else {
						req.Reply(true, []byte("Transfer complete!\n"))
					}
				case "ready":
					if opt.cmd == "send" {
						content := readSecret(opt.infile)
						req.Reply(true, content)
					} else {
						fmt.Fprintf(os.Stderr, "alert: attempting to read file by remote cient\n")
					}

				default:
					fmt.Fprintf(os.Stderr, "warning: unknown SSH request type: %s\n", req.Type)
				}

			case <-timeout:
				fmt.Fprintf(os.Stderr, "warning: connection timeout, closing the session..\n")
			}

		}()

		if !opt.forever || acceptTimeout {
			break
		}

	}
}

func validateCmdOptions(opt cmdOptions) {

	if len(opt.proxy) == 0 && len(opt.connect) == 0 && len(opt.listen) == 0 {
		fmt.Fprintf(os.Stderr, "error: missing parameter. use -proxy or -connect or -listen option\n")
		os.Exit(2)
	}

	c := 0
	if len(opt.proxy) > 0 {
		c++
	}

	if len(opt.connect) > 0 {
		c++
	}

	if len(opt.listen) > 0 {
		c++
	}

	if c == 0 {
		fmt.Fprintf(os.Stderr, "error: missing parameter. use -proxy or -connect or -listen option\n")
		os.Exit(2)
	}

	if c > 1 {
		fmt.Fprintf(os.Stderr, "error: invalid options. cannot combine -proxy, -connect, -listen options (they are mutually exclusive)\n")
		os.Exit(2)
	}

	if len(opt.peerKeyFile) == 0 {
		if opt.cmd == "send" {
			fmt.Fprintf(os.Stderr, "error: missing parameter -receiver-pubkey\n")
		} else {
			fmt.Fprintf(os.Stderr, "error: missing parameter -sender-pubkey\n")
		}
		os.Exit(2)
	}

	//if len(opt.proxy) > 0 && len(opt.proxyKeyFile) == 0 {
	//	fmt.Fprintf(os.Stderr, "error: missing parameter -proxy-key\n")
	//	os.Exit(2)
	//}

	if opt.cmd == "receive" {
		if len(opt.keyFile) == 0 {
			fmt.Fprintf(os.Stderr, "error: missing parameter -key\n")
			os.Exit(2)
		}

		if len(opt.connect) > 0 && opt.forever {
			fmt.Fprintf(os.Stderr, "warning: unused parameter -dangerous-forever\n")
		}
	}

	if opt.cmd == "send" && len(opt.infile) == 0 {
		fmt.Fprintf(os.Stderr, "error: missing parameter -in-file\n")
		os.Exit(2)
	}

	if opt.quiet {
		stdout = ioutil.Discard
	}
}

func receiver(opt cmdOptions) {
	options := flag.NewFlagSet(opt.cmd, flag.ExitOnError)
	options.StringVar(&opt.connect, "connect", "", "Target host to connect; format: host:port (not required if you use -proxy)")
	options.StringVar(&opt.listen, "listen", "", "Listen on host:port; format: [host]:port (not required if you use -proxy)")
	options.StringVar(&opt.keyFile, "key", "~/.ssh/id_rsa", "SSH private key file to authenticate the receiver (mandatory field)")
	options.StringVar(&opt.proxy, "proxy", "", "Intermediate SSH server to connect; format: ssh://user@host[:port]] (not required if you use -listen)")
	options.StringVar(&opt.proxyKeyFile, "proxy-key", "", "SSH private key file for proxy authentication (default: use ssh-agent if configured)")
	options.StringVar(&opt.proxyKnownHostFile, "proxy-host-pubkey", "~/.ssh/known_hosts", "Proxy host public key file")
	options.StringVar(&opt.peerKeyFile, "sender-pubkey", "", "Sender's SSH public key file  - local filename or an HTTPS URL")
	options.StringVar(&opt.rfPort, "rf-port", "15432", "Proxy SSH RemoteForward port, used with -proxy option")
	options.BoolVar(&opt.overwrite, "overwrite", false, "Overwrites the output file if the file already exists")
	options.StringVar(&opt.outputDir, "dir", "~/.zcretshare", "Output file save directory")
	options.StringVar(&opt.cacert, "cacert", "", "x509 CA certificate bundle file; used for -receiver-pubkey HTTPS URL certificate validation. (default: use system CA bunde)")
	options.BoolVar(&opt.stdout, "dangerous-stdout", false, "Output secrets to stdout (warning: your secret may get exposed; not recommended)")
	options.BoolVar(&opt.forever, "dangerous-forever", false, "do not exit after processing first request, instead run for ever (not recommended)")
	options.BoolVar(&opt.quiet, "quiet", false, "supress all info messages on stdout")

	options.SetOutput(os.Stdout)
	options.Usage = func() {
		fmt.Fprintf(options.Output(), "Usage: zcretshare receive [-h] [options]\n\n")
		options.PrintDefaults()
		fmt.Fprintf(options.Output(), "\n  Valid options for -proxy:\n")
		fmt.Fprintf(options.Output(), "\t-key -sender-pubkey -proxy-key -proxy-host-pubkey -rf-port -overwrite -dir -dangerous-stdout -dangerous-forever -cacert -quiet\n")
		fmt.Fprintf(options.Output(), "  Valid options for -listen:\n")
		fmt.Fprintf(options.Output(), "\t-key -receiver-pubkey -overwrite -dir -dangerous-stdout -dangerous-forever -cacert -quiet\n")
		fmt.Fprintf(options.Output(), "  Valid options for -connect:\n")
		fmt.Fprintf(options.Output(), "\t-key -receiver-pubkey -overwrite -dir -dangerous-stdout -cacert -quiet\n")
		fmt.Fprintf(options.Output(), "\nExamples:\n")
		fmt.Fprintf(options.Output(), "\tzcretshare receive -listen <your-host-ip>:<15432> -key ~/.ssh/recv_id_rsa -sender-pubkey ~/.ssh/sender_id_rsa.pub\n\n")
		fmt.Fprintf(options.Output(), "\tzcretshare receive -proxy ssh://<user>@<proxy-ssh-server>:<22> -key ~/.ssh/recv_id_rsa -sender-pubkey https://example.com/sender/id_rsa.pub -dir /tmp\n\n")
		fmt.Fprintf(options.Output(), "\tzcretshare receive -proxy ssh://<user>@<proxy-ssh-server>:<22> -key ~/.ssh/recv_id_rsa -proxy-key ~/.ssh/id_rsa_proxy -sender-pubkey ~/.ssh/sender_id_rsa.pub -dir /tmp\n\n")
		fmt.Fprintf(options.Output(), "\tzcretshare receive -connect ssh://<receiver-host>:<15432> -key recv_id_rsa -sender-pubkey sender_id_rsa.pub -overwrite -dir /tmp\n\n")
		os.Exit(0)
	}

	options.Parse(os.Args[2:])
	validateCmdOptions(opt)
	opt.proxyKnownHostFile = tildeExpand(opt.proxyKnownHostFile)
	opt.keyFile = tildeExpand(opt.keyFile)
	opt.outputDir = tildeExpand(opt.outputDir)

	if len(opt.connect) > 0 {
		connect(opt)
	} else {
		listen(opt)
	}
}

func sender(opt cmdOptions) {
	options := flag.NewFlagSet(opt.cmd, flag.ExitOnError)
	options.StringVar(&opt.connect, "connect", "", "Target host to connect; format: host:port (not required if you use -proxy)")
	options.StringVar(&opt.listen, "listen", "", "Listen on host:port; format: [host]:port (not required if you use -proxy)")
	options.StringVar(&opt.keyFile, "key", "", "SSH private key file for authentication (default: use ssh-agent if configured)")
	options.StringVar(&opt.proxy, "proxy", "", "Intermediate SSH server to connect; format: ssh://user@host[:port] (not required if you use -connect)")
	options.StringVar(&opt.proxyKeyFile, "proxy-key", "", "SSH private key file for proxy authentication (default: use ssh-agent if configured)")
	options.StringVar(&opt.proxyKnownHostFile, "proxy-host-pubkey", "~/.ssh/known_hosts", "Proxy host public key file")
	options.StringVar(&opt.peerKeyFile, "receiver-pubkey", "", "Receiver's SSH public key/cert - local filename or an HTTPS URL")
	options.StringVar(&opt.infile, "in-file", "", "Secret file to share with the remote party")
	options.StringVar(&opt.rfPort, "rf-port", "15432", "Proxy SSH RemoteForward port, used with -proxy option")
	options.StringVar(&opt.cacert, "cacert", "", "X.509 CA certificate bundle file; used for -receiver-pubkey HTTPS URL certificate validation. (default: use system CA bunde)")
	options.BoolVar(&opt.quiet, "quiet", false, "Supress all info messages on stdout")
	options.BoolVar(&opt.forever, "dangerous-forever", false, "Skip exiting after first request, instead run for ever (not recommended)")

	options.SetOutput(os.Stdout)
	options.Usage = func() {
		fmt.Fprintf(options.Output(), "Usage: zcretshare send [-h] [options]\n\n")
		options.PrintDefaults()
		fmt.Fprintf(options.Output(), "\n  Valid options for -proxy:\n")
		fmt.Fprintf(options.Output(), "\t-key -receiver-pubkey -proxy-key -proxy-host-pubkey -rf-proxy -in-file -cacert -quiet\n")
		fmt.Fprintf(options.Output(), "  Valid options for -connect:\n")
		fmt.Fprintf(options.Output(), "\t-key -receiver-pubkey -in-file -cacert -quiet\n")
		fmt.Fprintf(options.Output(), "  Valid options for -listen:\n")
		fmt.Fprintf(options.Output(), "\t-key -receiver-pubkey -in-file -dangerous-forever -cacert -quiet\n")
		fmt.Fprintf(options.Output(), "\nExamples:\n")
		fmt.Fprintf(options.Output(), "\tzcretshare send -connect ssh://<receiver-host>:<15432> -key ~/.ssh/id_rsa -in-file ~/secret-file.txt -receiver-pubkey ~/.ssh/recv_id_rsa.pub\n\n")
		fmt.Fprintf(options.Output(), "\tzcretshare send -proxy ssh://<user>@<proxy-ssh-server>:<22> -key ~/.ssh/id_rsa -in-file ~/secret-file.txt -receiver-pubkey https://example.com/receiver/id_rsa.pub\n\n")
		fmt.Fprintf(options.Output(), "\tzcretshare send -proxy ssh://<user>@<proxy-ssh-server>:<22> -proxy-key ~/.ssh/id_rsa_proxy -in-file ~/secret-file.txt -receiver-pubkey ~/.ssh/recv_id_rsa.pub\n\n")
		fmt.Fprintf(options.Output(), "\tzcretshare send -listen 0:<15432> -key sender_id_rsa -receiver-pubkey recv_id_rsa.pub -in-file super-secret.txt\n\n")
		os.Exit(0)
	}

	options.Parse(os.Args[2:])
	validateCmdOptions(opt)
	opt.proxyKnownHostFile = tildeExpand(opt.proxyKnownHostFile)
	opt.keyFile = tildeExpand(opt.keyFile)

	if len(opt.listen) > 0 {
		listen(opt)
	} else {
		connect(opt)
	}
}

func main() {

	if len(os.Args) == 1 || os.Args[1] == "-h" || os.Args[1] == "--help" {
		fmt.Fprintln(os.Stdout, "Usage: zcretshare <command> [-h] [<args>]")
		fmt.Fprintln(os.Stdout, "The commands are: ")
		fmt.Fprintln(os.Stdout, " send     To send secrets")
		fmt.Fprintln(os.Stdout, " receive  Receive secrets")
		fmt.Fprintln(os.Stdout, " version  Release version")
		fmt.Fprintln(os.Stdout, " man      Manpage (try 'zcretshare man | more')")
		os.Exit(0)
	}

	if len(os.Args) == 1 || os.Args[1] == "version" || os.Args[1] == "-version" || os.Args[1] == "--version" {
		fmt.Printf("zcretshare %s %s/%s %s\n", versionNumber, runtime.GOOS, runtime.GOARCH, releaseDate)
		os.Exit(0)
	}

	var opt cmdOptions
	switch os.Args[1] {
	case "send":
		opt.cmd = "send"
		sender(opt)
	case "receive":
		opt.cmd = "receive"
		receiver(opt)
	case "man":
		fmt.Fprintln(os.Stdout, manPages())
	default:
		fmt.Fprintf(os.Stderr, "%q is not valid command.\n", os.Args[1])
		os.Exit(2)
	}
}

func manPages() string {
	return `
NAME
     zcretshare -- a command-line tool to share secret/key materials between two (or more) users using SSH keys

SYNOPSIS
     zcretshare <command> [-h] [<args>]

     The commands are:
       send     To send secrets
       receive  Receive secrets
       version  Release version
       man      Manpage

DESCRIPTION
     zcretshare provides a reasonably secure mechanism to share secrets with your co-workers. As an engineer your often would have
     enountered situations where you need to share key materials (secrets, key files, license keys etc.) with your co-workers.
     The common, but insecure practice is to share it over IM/chat channel or email. Sharing secrets through these communication
     channels expose those secrets to their servers in unencrypted form. This poses a significant security risk
     to the company. Though GPG encryption is the recommended practice, it is not widely used because: (a) not many engineers have
     their GPG keys handy with them or published, (b) difficulty for the users to learn and use (poor usability)

     zcretshare features:
     * Setup a secure tunnel between workstations and share secrets over it
     * Use your existing SSH keys and ssh-agent, no need to create or manage other kinds of keys
     * Usable security: Intuitive to use. Simple send and receive commands
     * Stream the secret over secure tunnel; no need to encrypt, store and forward data - common with GPG encryption and similar tools.
       Since PGP encrypted data are typically send over email, multiple copies of encrypted data end up in 3rd party mail servers.
     * Perfect Forward Secrecy

     Cons:
     * Both sender and receiver have to be online to make this work
     * Depends on third party to authenticate peer's public key - hence more suitable in trusted environments, for instance,
       your organiation/employer can acts as a trusted third party between sender and receiver
     * Not suitable for sharing files larger than 200KB (may increace the limit later)

		 +------------+     SSH       +----------+     SSH      +------------+
		 |   sender   | ------------> |  proxy   | <----------- |  receiver  |
		 |            | --------------|----------|------------> |            |
		 +------------+      SSH      +----------+              +------------+

		 +------------+                   SSH                   +------------+
		 |   sender   | --------------------------------------> |  receiver  |
		 |  (connect) |                                         |  (listen)  |
		 +------------+                                         +------------+

		 +------------+                   SSH                   +------------+
		 |   sender   | <-------------------------------------- |  receiver  |
		 |  (listen)  |                                         |  (connect) |
		 +------------+                                         +------------+

     Why SSH keys?
     * Most engineers are familiar with SSH and its usage.
     * If you are an engineer, you likely have SSH keys to login to remote machines as part of your job - means you can use the same keys,
       no need to manage additional keys.
     * No additional software required for proxy server. It just works with stock SSH daemon.

     Arguments used with 'send' and 'receive' commands

     -cacert string
          x509 CA certificate bundle file; used for -receiver-pubkey HTTPS URL certificate validation. (default: use system CA bunde)

     -connect string
          Target host to connect; format: host:port (not required if you use -proxy)

     -dangerous-forever
          Skip exiting after first request, instead run for ever (not recommended)

     -dangerous-stdout
          Output secrets to stdout (warning: your secret may get exposed; not recommended)
          This option can be used to pipe the zcretshare output to programs like unzip

     -dir string
          Output file save directory (default "~/.zcretshare")

     -in-file string
          Secret file to share with the remote party. Used with 'send' command. Use '-' to read from stdin.
          Note - stdio is a convenience function that enable you combine zcretshare with other Unix tools
          like zip. It is not suitable to stream continious data.

     -key string
          SSH private key file to authenticate the receiver (mandatory field for listener) (default "~/.ssh/id_rsa")

     -listen string
          Listen on host:port; format: [host]:port (not required if you use -proxy)

     -overwrite
          Overwrites the output file if the file already exists

     -proxy string
          Intermediate SSH server to connect; format: ssh://user@host[:port]] (not required if you use -listen)

     -proxy-host-pubkey string
          Proxy host public key file (default "~/.ssh/known_hosts")

     -proxy-key string
          SSH private key file for proxy authentication (default: use ssh-agent if configured)

     -quiet
          Supress all info messages on stdout

     -rf-port string
          Proxy SSH RemoteForward port, used with -proxy option (default "15432")

     -receiver-pubkey string
          Receiver's SSH public key/cert - local filename or an HTTPS URL. Used with 'send' command

     -sender-pubkey string
          Sender's SSH public key file  - local filename or an HTTPS URL


     Valid options for 'send -proxy':
          -key -receiver-pubkey -proxy-key -proxy-host-pubkey -rf-proxy -in-file -cacert -quiet
          A proxy is used when both sender and receiver cannot reach each other directly. Proxy is a SSH server reachable by both parties, and can be hosted in cloud (AWS, GCP, Azure etc.)

     Valid options for 'send -connect':
          -key -receiver-pubkey -in-file -cacert -quiet
          Used if the sender can directly reach receiver host over network

     Valid options for 'send -listen':
          -key -receiver-pubkey -in-file -dangerous-forever -cacert -quiet
          Used if the receiver can reach sender but not the otherway. For example, the receiver would be inside a firewall'd network or using private IP, hence not directly reachable by sender.

     Valid options for 'receive -proxy':
          -key -sender-pubkey -proxy-key -proxy-host-pubkey -rf-port -overwrite -dir -dangerous-stdout -dangerous-forever -cacert -quiet
          A proxy is used when both sender and receiver cannot reach each other directly

     Valid options for 'receive -listen':
          -key -sender-pubkey -overwrite -dir -dangerous-stdout -dangerous-forever -cacert -quiet
          Used if the sender can directly reach receiver host over network

     Valid options for 'receive -connect':
          -key -sender-pubkey -overwrite -dir -dangerous-stdout -cacert -quiet
          Used if the receiver can reach sender but not the otherway. For example, the receiver would be inside a firewall'd network or using private IP, hence not directly reachable by sender.

     Sharing public keys
     The easiest way to exchange public keys between users is to use out-of-band channels - for example, Slack channel, email, GitHub etc.

EXAMPLES
     zcretshare send -connect ssh://<receiver-host>:<15432> -key sender_id_rsa -receiver-pubkey ~/.ssh/recv_id_rsa.pub -in-file ~/secret-file.txt
     zcretshare receive -listen <your-host>:<15432> -key ~/.ssh/recv_id_rsa  -sender-pubkey ~/.ssh/sender_id_rsa.pub

     zcretshare send -proxy ssh://<user>@<proxy-ssh-server>:<22> -key sender_id_rsa -receiver-pubkey https://example.com/receiver/id_rsa.pub -in-file ~/secret-file.txt
     zcretshare receive -proxy ssh://<user>@<proxy-ssh-server>:<22> -key ~/.ssh/recv_id_rsa  -sender-pubkey https://example.com/sender/id_rsa.pub -dir /tmp

     zcretshare send -proxy ssh://<user>@<proxy-ssh-server>:<22> -proxy-key ~/.ssh/id_rsa_proxy -receiver-pubkey ~/.ssh/recv_id_rsa.pub -in-file ~/secret-file.txt
     zcretshare receive -proxy ssh://<user>@<proxy-ssh-server>:<22> -key ~/.ssh/recv_id_rsa  -proxy-key ~/.ssh/id_rsa_proxy -sender-pubkey ~/.ssh/sender_id_rsa.pub -dir /tmp

     zcretshare send -listen <receiver-host>:<15432> -key sender_id_rsa -receiver-pubkey recv_id_rsa.pub -in-file super-secret.txt
     zcretshare receive -connect ssh://<receiver-host>:<15432> -key recv_id_rsa -sender-pubkey sender_id_rsa.pub -overwrite -dir /tmp

     zcretshare man | less

ENVIRONMENT
     SSH_AUTH_SOCK - used to connect ssh-agent
     HOME - used to locate user home directory

FILES
     ${HOME}/.zcretshare - default directory where the receiver stores secret files

SEE ALSO
     https://github.com/prbinu/zcretshare

AUTHOR
    Binu Ramakrishnan

COPYRIGHT
    Copyright (c) 2019, NVIDIA CORPORATION. All rights reserved.

`
}
