package webpush

import (
	"net/http"
	"testing"
	"time"

	"github.com/valyala/fasthttp"
)

func TestClient_Send(t *testing.T) {
	client, err := NewClient(ClientOptions{
		FastHTTPClient: &fasthttp.Client{},
		JWTDuration:    24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("unexpected err: %+v", err)
	}

	// This is test subscription gotten by running example/index.html.
	subscription := &Subscription{
		Endpoint: "https://fcm.googleapis.com/fcm/send/eta_1ywSsss:APA91bFwU-avS6dn5Tpm8TZRk-Bu5_QCK776ZNJnU5trXRXflzBrElt0GQUUzSH2mP6sIGf_s5wImoH97Vl3eSq2eoW5Q4wL8FWTXPWWHaphDVmnwQGSd7Rrf_t7JW0DWKvQwfqx9fz7",
		Keys: Keys{
			Auth:   "Nmblyrdw7oHyQPemcmg7wg",
			P256dh: "BPWugBU2WfrKxuXVOS1o0UOrW83slP1eqw8w4T6GgLC22Tkv89RgL-B5eJiNYy-_T5QylXWQnjUwF4L92RKVvng",
		},
	}

	sendOptions := &SendOptions{
		TTL:        8600,
		Urgency:    UrgencyNormal,
		Subscriber: "test@example.com",
		// Keys generated using https://www.attheminute.com/vapid-key-generator
		VAPIDPublicKey:  "BInM_lCdkF2EzNXuD9lV2ac-HpB4tCGIav11s6Ty4y2T-9Nc870AiIbW6-Is7e7dizSOp9f_dHpjtym26c-79HU",
		VAPIDPrivateKey: "YzgTWo9yqyVsgrsrx9-92-yF5Xc7NguDSANYFnAmisk",
	}

	t.Run("empty", func(t *testing.T) {
		status, err := client.Send(subscription, sendOptions, nil)
		if err != nil {
			t.Fatalf("unexpected err: %+v", err)
		}
		if status != http.StatusCreated {
			t.Fatalf("unexpected status: %d", status)
		}
	})

	t.Run("with payload", func(t *testing.T) {
		status, err := client.Send(subscription, sendOptions, []byte(`{"url": "https://google.com"}`))
		if err != nil {
			t.Fatalf("unexpected err: %+v", err)
		}
		if status != http.StatusCreated {
			t.Fatalf("unexpected status: %d", status)
		}
	})
}
