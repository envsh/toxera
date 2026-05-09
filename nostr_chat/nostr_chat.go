package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"fiatjaf.com/nostr"
)

type appState struct {
	sk       nostr.SecretKey
	pk       nostr.PubKey
	kind     nostr.Kind
	peerPK   string
	havePeer bool
	appTag   string
	relayURL string
	keyFile  string
}

func loadKey(path string) (sk nostr.SecretKey, pk nostr.PubKey, err error) {
	f, err := os.Open(path)
	if err != nil {
		return sk, pk, err
	}
	defer f.Close()

	var secHex string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "sec=") && len(line) == 4+64 {
			secHex = line[4:]
			break
		}
	}
	if secHex == "" {
		return sk, pk, errors.New("invalid key file")
	}

	sk, err = nostr.SecretKeyFromHex(secHex)
	if err != nil {
		return sk, pk, err
	}
	return sk, sk.Public(), nil
}

func saveKey(path string, sk nostr.SecretKey) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	pk := sk.Public()
	fmt.Fprintf(f, "pub=%s\nsec=%s\n", strings.ToUpper(pk.Hex()), strings.ToUpper(sk.Hex()))
	return nil
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Usage: %s [options]

Connect to a Nostr relay using ephemeral events for chat.

Options:
  -r RELAY     WebSocket URL (default: wss://relay.damus.io)
  -k KIND      Event kind (default: 22334)
  -f FILE      Key file path (default: nostr.key)
  -p PUBKEY    Peer pubkey hex for directed messages
  -a NAME      App tag name for namespace isolation
  -h           Show this help message

Commands:
  /quit        Exit the program
`, os.Args[0])
}

func main() {
	var showHelp bool
	var relayURL string
	var kind int
	var keyFile string
	var peerHex string
	var appTag string

	flag.BoolVar(&showHelp, "h", false, "show help")
	flag.StringVar(&relayURL, "r", "wss://relay.damus.io", "relay URL")
	flag.IntVar(&kind, "k", 22334, "event kind")
	flag.StringVar(&keyFile, "f", "nostr.key", "key file")
	flag.StringVar(&peerHex, "p", "", "peer pubkey")
	flag.StringVar(&appTag, "a", "", "app tag")

	flag.Usage = printUsage
	flag.Parse()

	if showHelp {
		printUsage()
		return
	}

	// normalise peer hex to lowercase for protocol consistency
	if peerHex != "" {
		peerHex = strings.ToLower(peerHex)
	}

	st := appState{
		kind:     nostr.Kind(kind),
		peerPK:   peerHex,
		havePeer: peerHex != "",
		appTag:   appTag,
		relayURL: relayURL,
		keyFile:  keyFile,
	}

	var err error
	st.sk, st.pk, err = loadKey(keyFile)
	if err != nil {
		st.sk = nostr.Generate()
		st.pk = st.sk.Public()
		if err := saveKey(keyFile, st.sk); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to save key: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Generated new key, saved to %s\n", keyFile)
	} else {
		fmt.Printf("Loaded key file %s\n", keyFile)
	}

	fmt.Printf("My pubkey: %s\n", strings.ToUpper(st.pk.Hex()))

	if st.havePeer {
		if _, err := nostr.PubKeyFromHex(peerHex); err != nil {
			fmt.Fprintf(os.Stderr, "Invalid peer pubkey: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Peer pubkey: %s\n", strings.ToUpper(peerHex))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	relay, err := nostr.RelayConnect(ctx, relayURL, nostr.RelayOptions{
		NoticeHandler: func(r *nostr.Relay, notice string) {
			fmt.Printf("\n[relay NOTICE] %s\n> ", notice)
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to connect: %v\n", err)
		os.Exit(1)
	}
	defer relay.Close()

	fmt.Printf("Connected to %s\nkind=%d\n", relayURL, kind)

	filter := nostr.Filter{Kinds: []nostr.Kind{st.kind}}
	if st.havePeer {
		filter.Tags = nostr.TagMap{"p": []string{st.pk.Hex()}}
	}

	sub, err := relay.Subscribe(ctx, filter, nostr.SubscriptionOptions{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to subscribe: %v\n", err)
		os.Exit(1)
	}

	go func() {
		for evt := range sub.Events {
			if evt.PubKey == st.pk {
				continue
			}
			if st.appTag != "" {
				if evt.Tags.FindWithValue("app", st.appTag) == nil {
					continue
				}
			}
			fmt.Printf("<<< %s\n", evt.String())
			disp := strings.ToUpper(evt.PubKey.Hex())
			fmt.Printf("\n[%.8s] %s\n> ", disp, evt.Content)
		}
	}()

	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("> ")
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r\n")
		if line == "" {
			fmt.Print("> ")
			continue
		}
		if line == "/quit" {
			fmt.Println("Quitting...")
			cancel()
			break
		}

		evt := nostr.Event{
			CreatedAt: nostr.Now(),
			Kind:      st.kind,
			Tags:      nostr.Tags{},
			Content:   line,
		}
		if st.havePeer {
			evt.Tags = append(evt.Tags, nostr.Tag{"p", st.peerPK})
		}
		if st.appTag != "" {
			evt.Tags = append(evt.Tags, nostr.Tag{"app", st.appTag})
		}

		if err := evt.Sign(st.sk); err != nil {
			fmt.Printf("\n[system] Sign failed: %v\n> ", err)
			continue
		}

		fmt.Printf(">>> %s\n", evt.String())

		if err := relay.Publish(ctx, evt); err != nil {
			fmt.Printf("[system] Publish failed: %v\n> ", err)
			continue
		}
		fmt.Print("> ")
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
	}
	// keep running if stdin closed (e.g. background mode, pipe)
	<-ctx.Done()
}
