package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
	"github.com/nbd-wtf/go-nostr/nip19"
	"github.com/nbd-wtf/nostr-sdk"
)

const name = "nostr-alert"

const version = "0.0.3"

var revision = "HEAD"

type payload struct {
	Alerts []struct {
		Annotations struct {
			Summary string `json:"summary"`
		} `json:"annotations"`
		DashboardURL string `json:"dashboardURL"`
		EndsAt       string `json:"endsAt"`
		Fingerprint  string `json:"fingerprint"`
		GeneratorURL string `json:"generatorURL"`
		Labels       struct {
			Alertname string `json:"alertname"`
			Instance  string `json:"instance"`
		} `json:"labels"`
		PanelURL    string      `json:"panelURL"`
		SilenceURL  string      `json:"silenceURL"`
		StartsAt    string      `json:"startsAt"`
		Status      string      `json:"status"`
		ValueString string      `json:"valueString"`
		Values      interface{} `json:"values"`
	} `json:"alerts"`
	CommonAnnotations struct {
		Summary string `json:"summary"`
	} `json:"commonAnnotations"`
	CommonLabels struct {
		Alertname string `json:"alertname"`
		Instance  string `json:"instance"`
	} `json:"commonLabels"`
	ExternalURL string `json:"externalURL"`
	GroupKey    string `json:"groupKey"`
	GroupLabels struct {
		Alertname string `json:"alertname"`
		Instance  string `json:"instance"`
	} `json:"groupLabels"`
	Message         string `json:"message"`
	OrgID           int64  `json:"orgId"`
	Receiver        string `json:"receiver"`
	State           string `json:"state"`
	Status          string `json:"status"`
	Title           string `json:"title"`
	TruncatedAlerts int64  `json:"truncatedAlerts"`
	Version         string `json:"version"`
}

func doPost(rh string, pk string, u string, content string) error {
	var sk string
	if _, s, err := nip19.Decode(pk); err == nil {
		sk = s.(string)
	} else {
		return err
	}
	ev := nostr.Event{}
	if npub, err := nostr.GetPublicKey(sk); err == nil {
		if _, err := nip19.EncodePublicKey(npub); err != nil {
			return err
		}
		ev.PubKey = npub
	} else {
		return err
	}

	ctx := context.Background()

	ev.Content = content
	var pub string
	if pp := sdk.InputToProfile(ctx, u); pp != nil {
		pub = pp.PublicKey
	} else {
		return fmt.Errorf("failed to parse pubkey from '%s'", u)
	}

	ev.Tags = ev.Tags.AppendUnique(nostr.Tag{"p", pub})
	ev.CreatedAt = nostr.Now()
	ev.Kind = nostr.KindEncryptedDirectMessage

	ss, err := nip04.ComputeSharedSecret(pub, sk)
	if err != nil {
		return err
	}
	ev.Content, err = nip04.Encrypt(ev.Content, ss)
	if err != nil {
		return err
	}
	if err := ev.Sign(sk); err != nil {
		return err
	}

	relay, err := nostr.RelayConnect(ctx, rh)
	if err != nil {
		return err
	}
	err = relay.Publish(ctx, ev)
	if err != nil {
		fmt.Fprintln(os.Stderr, relay.URL, err)
	}
	return nil
}

func handler(rh string, pk string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		u := r.URL.Query().Get("u")

		var p payload
		err := json.NewDecoder(r.Body).Decode(&p)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		content := p.Title + "\n" + p.Message
		err = doPost(rh, pk, u, content)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func main() {
	var rh string
	var ver bool

	flag.StringVar(&rh, "relay", "wss://yabu.me", "relay URL")
	//flag.BoolVar(&ver, "v", false, "show version")
	flag.Parse()

	if ver {
		fmt.Println(version)
		os.Exit(0)
	}

	nsec := os.Getenv("SENDER_NSEC")
	if nsec == "" {
		log.Fatal("SENDER_NSEC is not set")
	}

	http.HandleFunc("POST /", handler(rh, nsec))

	addr := ":" + os.Getenv("PORT")
	if addr == ":" {
		addr = ":8080"
	}
	log.Printf("started %v", addr)
	http.ListenAndServe(addr, nil)
}
