package webpush

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strconv"
	"time"

	"github.com/valyala/fasthttp"
	"golang.org/x/crypto/hkdf"
)

const defaultJWTDuration = 12 * time.Hour

type SendOptions struct {
	TTL             int     // Set the TTL on the endpoint POST request
	RecordSize      uint32  // Limit the record size (Optional, default is MaxRecordSize)
	Topic           string  // Set the Topic header to collapse a pending messages (Optional)
	Urgency         Urgency // Set the Urgency header to change a message priority (Optional)
	Subscriber      string  // Sub in VAPID JWT token
	VAPIDPublicKey  string  // VAPID public key, passed in VAPID Authorization header
	VAPIDPrivateKey string  // VAPID private key, used to sign VAPID JWT token
}

type ClientOptions struct {
	FastHTTPClient *fasthttp.Client
	// JWTCache is cache for JWT tokens, *noCache is used by default.
	JWTCache Cacher
	// SaltFunc used to generate salt to sign message, by default used FastRandSaltFunc.
	SaltFunc SaltFunc
	// JWTDuration is lifetime of vapid JWT tokens (default is defaultJWTDuration).
	JWTDuration time.Duration
}

type Client struct {
	httpClient  *fasthttp.Client
	cache       Cacher
	salt        SaltFunc
	jwtDuration time.Duration
}

func NewClient(options ClientOptions) (*Client, error) {
	client := &Client{
		httpClient:  options.FastHTTPClient,
		cache:       options.JWTCache,
		salt:        options.SaltFunc,
		jwtDuration: options.JWTDuration,
	}

	if client.httpClient == nil {
		return nil, errors.New("missing FastHTTPClient")
	}

	if client.cache == nil {
		client.cache = &noCache{}
	}

	if client.salt == nil {
		client.salt = FastRandSaltFunc
	}

	if client.jwtDuration == 0 {
		client.jwtDuration = defaultJWTDuration
	}

	if client.jwtDuration > 24*time.Hour {
		return nil, errors.New("wrong JWTDuration, must be <= 24 hours")
	}

	return client, nil
}

// Send sends web-push notification to Subscription.Endpoint client.
// It can send 2 types of notifications:
//  - empty, client will receive empty notification (body encryption is not used)
//  - with payload, client will receive notification with prepared campaign (payload will be encrypted using Subscription.Keys)
// The type of notification is chosen by checking payload bytes, 0 bytes means empty notification.
// In the result it returns status code of push response (201 is success).
func (c Client) Send(subscription *Subscription, options *SendOptions, payload []byte) (int, error) {
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	// Get VAPID Authorization header.
	vapidAuthHeader, err := c.getVAPIDAuthorizationHeader(
		c.jwtDuration,
		subscription.UniqueKey,
		subscription.Endpoint,
		options.Subscriber,
		options.VAPIDPublicKey,
		options.VAPIDPrivateKey,
	)
	if err != nil {
		return 0, err
	}

	req.SetRequestURI(subscription.Endpoint)
	req.Header.SetMethod(fasthttp.MethodPost)

	req.Header.Set("Content-Length", "0")
	req.Header.Set("Authorization", vapidAuthHeader)
	req.Header.Set("TTL", strconv.Itoa(options.TTL))

	// Check the optional headers.
	if len(options.Topic) > 0 {
		req.Header.Set("Topic", options.Topic)
	}

	if isValidUrgency(options.Urgency) {
		req.Header.Set("Urgency", string(options.Urgency))
	}

	// Attach notification payload for not empty push.
	if len(payload) > 0 {
		if err := c.setupEncryptedRequestBody(subscription.Keys, options.RecordSize, req, payload); err != nil {
			return 0, err
		}
	}

	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	if err := c.httpClient.Do(req, resp); err != nil {
		return 0, err
	}

	return resp.StatusCode(), nil
}

func (c Client) setupEncryptedRequestBody(keys Keys, size uint32, req *fasthttp.Request, payload []byte) error {
	// Authentication secret (auth_secret)
	authSecret, err := decodeSubscriptionKey(keys.Auth)
	if err != nil {
		return err
	}

	// dh (Diffie Hellman)
	dh, err := decodeSubscriptionKey(keys.P256dh)
	if err != nil {
		return err
	}

	// Generate 16 byte salt
	// TODO: also use sync.Pool to return []byte with 16 len
	salt, err := c.salt()
	if err != nil {
		return err
	}

	// Create the ecdh_secret shared key pair
	curve := elliptic.P256()

	// Application server key pairs (single use)
	localPrivateKey, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return err
	}

	localPublicKey := elliptic.Marshal(curve, x, y)

	// Combine application keys with dh
	sharedX, sharedY := elliptic.Unmarshal(curve, dh)
	if sharedX == nil {
		return errors.New("Unmarshal Error: Public key is not a valid point on the curve")
	}

	sx, _ := curve.ScalarMult(sharedX, sharedY, localPrivateKey)
	sharedECDHSecret := sx.Bytes()

	hash := sha256.New

	// ikm
	prkInfoBuf := getBufWithBytes([]byte("WebPush: info\x00"))
	defer storeBuf(prkInfoBuf)
	prkInfoBuf.Write(dh)
	prkInfoBuf.Write(localPublicKey)

	prkHKDF := hkdf.New(hash, sharedECDHSecret, authSecret, prkInfoBuf.Bytes())
	ikm, err := getHKDFKey(prkHKDF, 32)
	if err != nil {
		return err
	}

	// Derive Content Encryption Key
	contentEncryptionKeyInfo := []byte("Content-Encoding: aes128gcm\x00")
	contentHKDF := hkdf.New(hash, ikm, salt, contentEncryptionKeyInfo)
	contentEncryptionKey, err := getHKDFKey(contentHKDF, 16)
	if err != nil {
		return err
	}

	// Derive the Nonce
	nonceInfo := []byte("Content-Encoding: nonce\x00")
	nonceHKDF := hkdf.New(hash, ikm, salt, nonceInfo)
	nonce, err := getHKDFKey(nonceHKDF, 12)
	if err != nil {
		return err
	}

	// Cipher
	block, err := aes.NewCipher(contentEncryptionKey)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// Get the record size
	recordSize := size
	if recordSize == 0 {
		recordSize = MaxRecordSize
	}

	recordLength := int(recordSize) - 16

	// Encryption Content-Coding Header
	recordBuf := getBufWithBytes(salt)
	defer storeBuf(recordBuf)

	rs := make([]byte, 4)
	binary.BigEndian.PutUint32(rs, recordSize)

	recordBuf.Write(rs)
	recordBuf.Write([]byte{byte(len(localPublicKey))})
	recordBuf.Write(localPublicKey)

	// Data
	dataBuf := getBufWithBytes(payload)
	defer storeBuf(dataBuf)

	// Pad content to max record size - 16 - header
	// Padding ending delimeter
	dataBuf.Write([]byte("\x02"))
	if err := pad(dataBuf, recordLength-recordBuf.Len()); err != nil {
		return err
	}

	// Compose the ciphertext
	ciphertext := gcm.Seal([]byte{}, nonce, dataBuf.Bytes(), nil)
	recordBuf.Write(ciphertext)

	req.Header.Set("Content-Encoding", "aes128gcm")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Length", strconv.Itoa(len(ciphertext)))

	req.SetBody(recordBuf.Bytes())

	return nil
}

func (c Client) getVAPIDAuthorizationHeader(jwtDuration time.Duration, uniqueKey interface{}, endpoint string, subscriber string, vapidPublicKey string, vapidPrivateKey string) (string, error) {
	if uniqueKey == nil {
		return makeVAPIDAuthorizationHeader(
			jwtDuration,
			endpoint,
			subscriber,
			vapidPublicKey,
			vapidPrivateKey,
		)
	}

	return getVAPIDAuthorizationHeaderWithCache(
		jwtDuration,
		c.cache,
		uniqueKey,
		endpoint,
		subscriber,
		vapidPublicKey,
		vapidPrivateKey,
	)
}
