package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/jessevdk/go-flags"
	"golang.org/x/term"

	"github.com/xconnio/berncrypt/go"
	"github.com/xconnio/wamp-webrtc-go"
	"github.com/xconnio/wampproto-go/auth"
	"github.com/xconnio/wampshell"
	"github.com/xconnio/xconn-go"
)

const (
	defaultRealm             = "wampshell"
	nonceSize                = 12
	procedureInteractive     = "wampshell.shell.interactive"
	procedureExec            = "wampshell.shell.exec"
	procedureWebRTCOffer     = "wampshell.webrtc.offer"
	topicOffererOnCandidate  = "wampshell.webrtc.offerer.on_candidate"
	topicAnswererOnCandidate = "wampshell.webrtc.answerer.on_candidate"
)

func startInteractiveShell(session *xconn.Session, keys *wampshell.KeyPair) error {
	fd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return fmt.Errorf("failed to set raw mode: %w", err)
	}
	defer func() { _ = term.Restore(fd, oldState) }()

	progressChan := make(chan *xconn.Progress, 32)

	sendSize := func() *xconn.Progress {
		width, height, err := term.GetSize(fd)
		if err != nil {
			return nil
		}
		msg := fmt.Sprintf("SIZE:%d:%d", width, height)
		ciphertext, nonce, err := berncrypt.EncryptChaCha20Poly1305([]byte(msg), keys.Send)
		if err != nil {
			return nil
		}
		payload := append(nonce, ciphertext...)
		return xconn.NewProgress(payload)
	}

	if p := sendSize(); p != nil {
		progressChan <- p
	}

	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGWINCH)
		for range sigChan {
			if p := sendSize(); p != nil {
				progressChan <- p
			}
		}
	}()

	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil {
				close(progressChan)
				return
			}
			ciphertext, nonce, err := berncrypt.EncryptChaCha20Poly1305(buf[:n], keys.Send)
			if err != nil {
				fmt.Fprintln(os.Stderr, "encryption error:", err)
				continue
			}
			progressChan <- xconn.NewProgress(append(nonce, ciphertext...))
		}
	}()

	decryptAndWrite := func(encData []byte) error {
		if len(encData) < nonceSize {
			return fmt.Errorf("invalid payload from server")
		}
		plain, err := berncrypt.DecryptChaCha20Poly1305(encData[nonceSize:], encData[:nonceSize], keys.Receive)
		if err != nil {
			return fmt.Errorf("decryption error: %w", err)
		}
		_, err = os.Stdout.Write(plain)
		return err
	}

	call := session.Call(procedureInteractive).
		ProgressSender(func(ctx context.Context) *xconn.Progress {
			p, ok := <-progressChan
			if !ok {
				return xconn.NewFinalProgress()
			}
			return p
		}).
		ProgressReceiver(func(result *xconn.InvocationResult) {
			if len(result.Args) > 0 {
				if err := decryptAndWrite(result.Args[0].([]byte)); err != nil {
					fmt.Fprintln(os.Stderr, err)
				}
			} else {
				_ = term.Restore(fd, oldState)
				os.Exit(0)
			}
		}).Do()

	if call.Err != nil {
		return fmt.Errorf("shell error: %w", call.Err)
	}
	return nil
}

func runCommand(session *xconn.Session, keys *wampshell.KeyPair, args []string) error {
	b := []byte(strings.Join(args, " "))

	ciphertext, nonce, err := berncrypt.EncryptChaCha20Poly1305(b, keys.Send)
	if err != nil {
		return fmt.Errorf("encryption error: %w", err)
	}

	payload := append(nonce, ciphertext...)

	callResponse := session.Call(procedureExec).Args(payload).Do()
	if callResponse.Err != nil {
		return fmt.Errorf("command execution failed: %w", callResponse.Err)
	}

	encryptedOutput, err := callResponse.Args.Bytes(0)
	if err != nil {
		return fmt.Errorf("output parsing error: %w", err)
	}

	plainOutput, err := berncrypt.DecryptChaCha20Poly1305(encryptedOutput[nonceSize:],
		encryptedOutput[:nonceSize], keys.Receive)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}
	fmt.Print(string(plainOutput))
	return nil
}

type Options struct {
	Interactive bool   `short:"i" long:"interactive" description:"Force interactive shell"`
	PeerToPeer  bool   `long:"p2p" description:"Use WebRTC for peer-to-peer connection"`
	Realm       string `long:"realm" description:"Realm to access"`
	Args        struct {
		Target string   `positional-arg-name:"host" required:"true"`
		Cmd    []string `positional-arg-name:"command"`
	} `positional-args:"yes"`
}

func main() {
	var opts Options
	parser := flags.NewParser(&opts, flags.Default)

	_, err := parser.Parse()
	if err != nil {
		log.Fatalln(err)
	}

	realm := opts.Realm
	if realm == "" {
		realm = defaultRealm
	}

	target := opts.Args.Target
	args := opts.Args.Cmd

	var host, port string
	if strings.Contains(target, "@") {
		parts := strings.SplitN(target, "@", 2)
		_, host = parts[0], parts[1]
	} else {
		user := os.Getenv("USER")
		if user == "" {
			log.Fatalln("Error: user not provided and $USER not set")
		}
		host = target
	}

	if strings.Contains(host, ":") {
		hp := strings.SplitN(host, ":", 2)
		host, port = hp[0], hp[1]
	} else {
		port = "8022"
	}

	privateKey, err := wampshell.ReadPrivateKeyFromFile()
	if err != nil {
		log.Fatalf("Error reading private key: %s", err)
	}

	authenticator, err := auth.NewCryptoSignAuthenticator("", privateKey, nil)
	if err != nil {
		log.Fatal("Error creating crypto sign authenticator:", err)
	}

	client := xconn.Client{
		SerializerSpec: wampshell.CapnprotoSerializerSpec,
		Authenticator:  authenticator,
	}

	url := fmt.Sprintf("rs://%s:%s", host, port)

	session, err := client.Connect(context.Background(), url, realm)
	if err != nil {
		log.Fatalf("Failed to connect via TCP: %v", err)
	}

	if opts.PeerToPeer {
		config := &wamp_webrtc_go.ClientConfig{
			Realm:                    realm,
			ProcedureWebRTCOffer:     procedureWebRTCOffer,
			TopicAnswererOnCandidate: topicAnswererOnCandidate,
			TopicOffererOnCandidate:  topicOffererOnCandidate,
			Serializer:               xconn.CBORSerializerSpec,
			Authenticator:            authenticator,
			Session:                  session,
		}

		session, err = wamp_webrtc_go.ConnectWAMP(config)
		if err != nil {
			log.Fatalf("Failed to connect via WebRTC: %v", err)
		}
	}

	keys, err := wampshell.ExchangeKeys(session)
	if err != nil {
		log.Fatalf("Failed to exchange keys: %v", err)
	}

	if opts.Interactive || len(args) == 0 {
		err := startInteractiveShell(session, keys)
		if err != nil {
			log.Fatal(err)
		}
	}

	err = runCommand(session, keys, args)
	if err != nil {
		log.Fatal(err)
	}
}
