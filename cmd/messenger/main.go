package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/scrypt"
)

var userID = "anon"
var rendezvousURL = "http://localhost:8080/join" // change to your public server URL

type Peer struct {
	Addr string `json:"addr"`
}

// derivePSK derives a stable pre-shared key from the room passphrase using scrypt
func derivePSK(passphrase string) []byte {
	salt := []byte("shadowchat-room-salt-v1")
	key, err := scrypt.Key([]byte(passphrase), salt, 1<<15, 8, 1, 32) // N=32768
	if err != nil {
		panic(err)
	}
	return key
}

// deriveSessionKey: HKDF(SHA256, shared || psk) -> 32 bytes
func deriveSessionKey(shared, psk []byte) []byte {
	// Mix shared and PSK with HMAC to make a stable input to HKDF
	h := hmac.New(sha256.New, psk)
	h.Write(shared)
	mix := h.Sum(nil)

	salt := make([]byte, 32) // zero salt is fine for HKDF here; we already mixed with PSK
	info := []byte("shadowchat session key")
	kdf := hkdf.New(sha256.New, mix, salt, info)
	key := make([]byte, 32)
	if _, err := io.ReadFull(kdf, key); err != nil {
		panic(err)
	}
	return key
}

// getPeers registers with rendezvous server and obtains peers list
func getPeers(roomKey string, listenAddr string) ([]Peer, error) {
	url := fmt.Sprintf("%s?room=%s&addr=%s", rendezvousURL, roomKey, listenAddr)
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var peers []Peer
	if err := json.NewDecoder(resp.Body).Decode(&peers); err != nil {
		return nil, err
	}
	return peers, nil
}

// helper: base64 encode
func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
func b64d(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

// sendRaw sends a raw UDP packet to an address
func sendRaw(conn *net.UDPConn, addr string, data []byte) error {
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	_, err = conn.WriteToUDP(data, raddr)
	return err
}

// perform ephemeral X25519 handshake with a peer and return AEAD cipher
// handshakeMessages are plain (public keys) — that's acceptable; we rely on DH + PSK for secrecy
func performHandshake(conn *net.UDPConn, peerAddr string, psk []byte, timeout time.Duration) (aead cipherWrapper, err error) {
	// generate ephemeral keypair
	var epPriv [32]byte
	var epPub [32]byte
	if _, err := rand.Read(epPriv[:]); err != nil {
		return aead, fmt.Errorf("ephemeral key gen: %w", err)
	}
	curve25519.ScalarBaseMult(&epPub, &epPriv)

	// send HS1 message containing our ephemeral public key
	hs1 := "HS1:" + b64(epPub[:])
	if err := sendRaw(conn, peerAddr, []byte(hs1)); err != nil {
		return aead, fmt.Errorf("send HS1: %w", err)
	}

	// set read deadline
	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 4096)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			return aead, fmt.Errorf("handshake read: %w", err)
		}
		if src.String() != peerAddr {
			// ignore other addresses
			continue
		}
		msg := string(buf[:n])
		if strings.HasPrefix(msg, "HS1:") {
			// peer also sent HS1; respond with HS2 containing our ephemeral public key
			// parse their pub
			b, err := b64d(strings.TrimPrefix(msg, "HS1:"))
			if err != nil || len(b) != 32 {
				continue
			}
			var peerPub [32]byte
			copy(peerPub[:], b)

			// compute shared secret
			var shared [32]byte
			curve25519.ScalarMult(&shared, &epPriv, &peerPub)

			// send HS2 with our ephemeral public
			hs2 := "HS2:" + b64(epPub[:])
			if err := sendRaw(conn, peerAddr, []byte(hs2)); err != nil {
				return aead, fmt.Errorf("send HS2: %w", err)
			}

			// derive session key
			sessionKey := deriveSessionKey(shared[:], psk)
			return newCipherWrapper(sessionKey)
		} else if strings.HasPrefix(msg, "HS2:") {
			// peer responded with their ephemeral pub
			b, err := b64d(strings.TrimPrefix(msg, "HS2:"))
			if err != nil || len(b) != 32 {
				continue
			}
			var peerPub [32]byte
			copy(peerPub[:], b)

			// compute shared secret
			var shared [32]byte
			curve25519.ScalarMult(&shared, &epPriv, &peerPub)

			sessionKey := deriveSessionKey(shared[:], psk)
			return newCipherWrapper(sessionKey)
		}
	}
}

// cipherWrapper abstracts AEAD (XChaCha20-Poly1305) operations
type cipherWrapper struct {
	aead cipher.AEAD
}

func newCipherWrapper(key []byte) (cipherWrapper, error) {
	a := cipherWrapper{}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return a, err
	}
	a.aead = aead
	return a, nil
}

func (c cipherWrapper) seal(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, chacha20poly1305.NonceSizeX) // 24 bytes
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := c.aead.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ct...), nil
}

func (c cipherWrapper) open(data []byte) ([]byte, error) {
	if len(data) < chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("too short")
	}
	nonce := data[:chacha20poly1305.NonceSizeX]
	ct := data[chacha20poly1305.NonceSizeX:]
	return c.aead.Open(nil, nonce, ct, nil)
}

// listenLoop receives incoming UDP packets and handles handshake/message framing
func listenLoop(conn *net.UDPConn, psk []byte, incoming chan<- string) {
	buf := make([]byte, 65536)
	// map peerAddr=>cipherWrapper for established sessions
	sessions := make(map[string]cipherWrapper)

	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		addr := src.String()
		msg := buf[:n]

		// If we already have a session with this peer, try decrypting
		if cw, ok := sessions[addr]; ok {
			plain, err := cw.open(msg)
			if err == nil {
				incoming <- string(plain)
				continue
			}
			// decryption failed: ignore or consider re-handshake
			continue
		}

		// Not an established session: check for HS1/HS2
		txt := string(msg)
		if strings.HasPrefix(txt, "HS1:") {
			// remote initiated; parse their ephemeral pub and respond with HS2
			b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(txt, "HS1:"))
			if err != nil || len(b) != 32 {
				continue
			}
			var peerPub [32]byte
			copy(peerPub[:], b)

			// create our ephemeral keypair
			var priv [32]byte
			var pub [32]byte
			if _, err := rand.Read(priv[:]); err != nil {
				continue
			}
			curve25519.ScalarBaseMult(&pub, &priv)

			// compute shared secret
			var shared [32]byte
			curve25519.ScalarMult(&shared, &priv, &peerPub)

			// send HS2 with our ephemeral pub
			hs2 := "HS2:" + base64.StdEncoding.EncodeToString(pub[:])
			_ = sendRaw(conn, addr, []byte(hs2))

			// derive session key and store session
			sessionKey := deriveSessionKey(shared[:], psk)
			cw, err := newCipherWrapper(sessionKey)
			if err == nil {
				sessions[addr] = cw
			}
			continue
		} else if strings.HasPrefix(txt, "HS2:") {
			// peer responded to our HS1; handled in performHandshake side usually
			// ignore here; performHandshake handles it synchronously
			continue
		} else {
			// could be an encrypted message from a peer who did handshake previously but we missed storing session
			// try deriving session with ephemeral fallback? cannot — skip
			continue
		}
	}
}

// joinChatRoom: discovers peers, performs handshake with each, and then enters chat
func joinChatRoom(roomKey string) {
	psk := derivePSK(roomKey)

	// create UDP listener on ephemeral port
	laddr, _ := net.ResolveUDPAddr("udp", ":0")
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		fmt.Println("UDP listen error:", err)
		return
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().String()
	fmt.Println("Local UDP", localAddr)

	// register and discover peers
	peers, err := getPeers(roomKey, localAddr)
	if err != nil {
		fmt.Println("Rendezvous error:", err)
		return
	}

	// incoming messages channel
	incoming := make(chan string, 64)
	go listenLoop(conn, psk, incoming)

	// perform handshake with peers concurrently to create sessions
	type sessRes struct {
		addr string
		cw   cipherWrapper
		err  error
	}
	// map to store sessions for sender loop
	sessions := make(map[string]cipherWrapper)

	for _, p := range peers {
		if p.Addr == localAddr {
			continue
		}
		// run handshake (synchronous short timeout)
		cw, err := performHandshake(conn, p.Addr, psk, 3*time.Second)
		if err != nil {
			fmt.Printf("Handshake with %s failed: %v\n", p.Addr, err)
			continue
		}
		sessions[p.Addr] = cw
		fmt.Println("Session established with", p.Addr)
	}

	// show that we entered chat
	fmt.Println("Entered chat. Type '/leave' to exit.")
	// chat input & sender loop
	stdin := bufio.NewScanner(os.Stdin)
	for stdin.Scan() {
		line := stdin.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		if line == "/leave" {
			fmt.Println("Leaving room...")
			return
		}
		plain := []byte(fmt.Sprintf("%s: %s", userID, line))

		// send to all established sessions
		for addr, cw := range sessions {
			ct, err := cw.seal(plain)
			if err != nil {
				fmt.Println("seal error:", err)
				continue
			}
			if err := sendRaw(conn, addr, ct); err != nil {
				fmt.Printf("send to %s error: %v\n", addr, err)
			}
		}
	}

	// concurrently print incoming messages
	go func() {
		for m := range incoming {
			fmt.Println(m)
		}
	}()
}

// main CLI loop
func main() {
	fmt.Println("====================================")
	fmt.Println("   ShadowChat — Noise-like P2P CLI  ")
	fmt.Println("====================================")
	fmt.Println("Commands:")
	fmt.Println("  id <name>         Set your identity")
	fmt.Println("  join-room <key>   Join/create a secure room")
	fmt.Println("  help              Show commands")
	fmt.Println("  exit              Quit")
	fmt.Println("====================================")

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("shadowchat> ")
		if !scanner.Scan() {
			break
		}
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		switch parts[0] {
		case "id":
			if len(parts) < 2 {
				fmt.Println("Usage: id <name>")
				continue
			}
			userID = parts[1]
			fmt.Printf("Identity set to %s\n", userID)
		case "join-room":
			if len(parts) < 2 {
				fmt.Println("Usage: join-room <key>")
				continue
			}
			fmt.Printf("Joining room with key: %s\n", parts[1])
			joinChatRoom(parts[1])
		case "help":
			fmt.Println("Commands:")
			fmt.Println("  id <name>         Set your identity")
			fmt.Println("  join-room <key>   Join/create a secure room")
			fmt.Println("  exit              Quit")
		case "exit":
			fmt.Println("Goodbye.")
			return
		default:
			fmt.Println("Unknown command, type 'help'")
		}
	}
}
