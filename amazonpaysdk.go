package amazonpaysdk

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha384"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)



func main() {

type AmazonPaySdk struct {
	MerchantID        string
	AccessKey         string
	SecretKey         string
	BaseURL           string
	CurrencyCode      string
	Sandbox           bool
	PlatformID        string
	ApplicationName   string
	ApplicationVersion string
	HandleThrottle    bool
}

var (
	apiPath = map[string]string{
		"RefundPayment":        "/v2/payments/refund",
		"GetRefundDetails":     "/v2/payments/refund/details",
		"ListOrderReference":   "/v2/payments/orderReference",
		"GetChargeStatus":      "/v2/payments/chargeStatus",
	}

	algorithm          = "AWS4-HMAC-SHA384"
	sha384             = "SHA-384"
	dateTimeFormat     = "20060102T150405Z"
	newLineCharacter   = "\n"
	terminationString  = "aws4_request"
	utcTimeZone        = "UTC"
	serviceName        = "AmazonPay"
	hmacAlgorithm      = "SHA384"
	region             = "eu-west-*"
	amazonBaseURL      = "amazonpay.amazon.in"
	amazonSandbox      = "true"
	amazonVerificationURL = "http://localhost:5000/verify" // "https://myURL/verify_signature"
	verificationStatus = "false"
	amazonPublicKey    = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq92yAzXaCQbGIid0mMBf
ulkGK8HqvAardDowtgbfGUZ+hIx6lhYKFMrluTr7bIlQ4qgJY85c9adkZSxHtr/D
hTV/ch5CCHDET3YC/DaFTKDp5t2uHKQAIb2Rl/73HQOd/pgImTiaLHPBr/gyz4iz
tYmlJQIm0vVuPktIANDGpK8qhizdztA3as1bLtILQZ5VtOjNn/xl1HQ+JDtBhUVr
13BuJPosecQz6ouhEtR+5i/grg6sUzayqPD1dY6AGRLR9ao/****************
BECuKoiARo7ItDfLameXJ1gLd8lkMzArIG275jbxAiPd4OcHHEfcqBADYB51FYDT
wQIDAQAB
-----END PUBLIC KEY-----`
)

type paramsSignAndEncrypt struct {
	OrderTotalAmount        bool
	OrderTotalCurrencyCode  bool
	SellerOrderID           bool
	CustomInformation      bool
	SellerNote             bool
	TransactionTimeout     bool
	IsSandbox              bool
	SellerStoreName        bool
}

type paramsSignAndEncryptGetChargeRequest struct {
	TransactionID         bool
	TransactionIDType     bool
}

type paramsVerifySignatureForProcessChargeResponse struct {
	TransactionID       bool
	Signature          bool
	PayURL             bool
}

type paramsVerifySignatureForChargeStatus struct {
	TransactionStatusCode       bool
	TransactionStatusDescription bool
	TransactionID              bool
	MerchantTransactionID      bool
	Signature                 bool
	TransactionValue           bool
	TransactionCurrencyCode    bool
	MerchantCustomData         bool
	TransactionDate            bool
}

type paramsVerifySignature struct {
	Description           bool
	ReasonCode            bool
	Status                bool
	Signature             bool
	SellerOrderID         bool
	AmazonOrderID         bool
	TransactionDate       bool
	OrderTotalAmount      bool
	OrderTotalCurrencyCode bool
	CustomInformation     bool
}

type paramsRefund struct {
	AmazonTransactionID   bool
	AmazonTransactionType bool
	RefundReferenceID     bool
	RefundAmount          bool
	CurrencyCode          bool
	MerchantID            bool
	SellerRefundNote      bool
	SoftDescriptor        bool
}

type paramsRefundDetails struct {
	AmazonRefundID   bool
	MerchantID       bool
}

type paramsListOrderReference struct {
	PaymentDomain                    bool
	QueryID                         bool
	QueryIDType                     bool
	MerchantID                       bool
	PageSize                        bool
	SortOrder                       bool
	OrderReferenceStatusListFilter  bool
	CreatedTimeRangeStart           bool
	CreatedTimeRangeEnd             bool
}

type paramsGetTransactionDetails struct {
	TransactionID       bool
	TransactionIDType   bool
}

func NewAmazonPaySdk(params map[string]interface{}) (*AmazonPaySdk, error) {
	sdk := &AmazonPaySdk{}

	for k, v := range params {
		switch k {
		case "merchant_id":
			sdk.MerchantID = v.(string)
		case "access_key":
			sdk.AccessKey = v.(string)
		case "secret_key":
			sdk.SecretKey = v.(string)
		case "base_url":
			sdk.BaseURL = v.(string)
		case "currency_code":
			sdk.CurrencyCode = v.(string)
		case "sandbox":
			sdk.Sandbox = v.(bool)
		case "platform_id":
			sdk.PlatformID = v.(string)
		case "application_name":
			sdk.ApplicationName = v.(string)
		case "application_version":
			sdk.ApplicationVersion = v.(string)
		case "handle_throttle":
			sdk.HandleThrottle = v.(bool)
		default:
			return nil, fmt.Errorf("key %s is either not part of the configuration or has incorrect key name", k)
		}
	}

	return sdk, nil
}

func (sdk *AmazonPaySdk) GetPaymentURL(params map[string]interface{}, redirectURL string) (string, error) {
	if redirectURL == "" {
		return "", fmt.Errorf("redirect URL cannot be null")
	}

	encryptedResponse, err := sdk.signAndEncryptParameters(params)
	if err != nil {
		return "", err
	}

	paymentURL := fmt.Sprintf("https://%s/initiatePayment?%s&redirectUrl=%s", amazonBaseURL, encryptedResponse, url.QueryEscape(redirectURL))
	return paymentURL, nil
}

func (sdk *AmazonPaySdk) VerifySignature(params map[string]interface{}) (bool, error) {
	if len(params) == 0 {
		return false, fmt.Errorf("payment response map cannot be empty")
	}

	if _, ok := params["verificationOperationName"]; ok {
		operationName := params["verificationOperationName"].(string)
		delete(params, "verificationOperationName")

		switch operationName {
		case "VERIFY_PROCESS_CHARGE_RESPONSE":
			checkForRequiredParameters(params, paramsVerifySignatureForProcessChargeResponse)
		case "VERIFY_CHARGE_STATUS":
			checkForRequiredParameters(params, paramsVerifySignatureForChargeStatus)
		default:
			checkForRequiredParameters(params, paramsVerifySignature)
		}
	} else {
		checkForRequiredParameters(params, paramsVerifySignature)
	}

	params = sdk.calculateSignForVerification(params)
	params["AWSAccessKeyId"] = sdk.AccessKey
	params["signatureMethod"] = "HmacSHA384"
	params["signatureVersion"] = 4

	providedSignature := params["signature"].(string)
	delete(params, "signature")

	signature := sdk.getSignature(params, "GET", sdk.BaseURL)

	if providedSignature == signature {
		return true, nil
	}
	return false, nil
}

func (sdk *AmazonPaySdk) signAndEncryptParameters(params map[string]interface{}) (string, error) {
	var operation string

	if _, ok := params["operationName"]; !ok {
		checkForRequiredParameters(params, paramsSignAndEncrypt)
		operation = "SIGN_AND_ENCRYPT"
	} else if params["operationName"].(string) == "SIGN_AND_ENCRYPT_GET_CHARGE_STATUS_REQUEST" {
		operation = params["operationName"].(string)
		delete(params, "operationName")
		checkForRequiredParameters(params, paramsSignAndEncryptGetChargeRequest)
	} else {
		return "", fmt.Errorf("%s is not a valid operation for sign and encrypt", params["operationName"].(string))
	}

	params = sdk.calculateSignForEncryption(params)
	params["AWSAccessKeyId"] = sdk.AccessKey
	params["signatureMethod"] = "HmacSHA384"
	params["signatureVersion"] = 4
	params["merchantId"] = sdk.MerchantID

	signature := sdk.getSignature(params, "GET", sdk.BaseURL)

	paramsString := sdk.getParamsString(params)
	paramsString += "&Signature=" + url.QueryEscape(signature)

	sessionKey := make([]byte, 16)
	_, _ = rand.Read(sessionKey)
	iv := make([]byte, 16)
	_, _ = rand.Read(iv)

	encryptedData := sdk.aesGCMEncrypt([]byte(paramsString), sessionKey, iv)

	encryptedSessionKey := sdk.rsaPublicEncrypt(sessionKey, []byte(amazonPublicKey))

	encryptedResponse := map[string]string{
		"payload": base64.StdEncoding.EncodeToString(encryptedData),
		"key":     base64.StdEncoding.EncodeToString(encryptedSessionKey),
		"iv":      base64.StdEncoding.EncodeToString(iv),
	}

	return sdk.getParamsString(encryptedResponse), nil
}

func (sdk *AmazonPaySdk) InitiateRefunds(requestParams map[string]interface{}) (string, error) {
	checkForRequiredParameters(requestParams, paramsRefund)

	params := map[string]interface{}{
		"Action": "RefundPayment",
	}

	fieldMappings := map[string]string{
		"merchant_id":           "SellerId",
		"amazon_transaction_id": "AmazonTransactionId",
		"amazon_transaction_type": "AmazonTransactionIdType",
		"refund_reference_id":   "RefundReferenceId",
		"refund_amount":         "RefundAmount.Amount",
		"currency_code":         "RefundAmount.CurrencyCode",
		"seller_refund_note":    "SellerRefundNote",
		"soft_descriptor":       "SoftDescriptor",
	}

	responseObject, err := sdk.setParamsAndPost(params, fieldMappings, requestParams)
	if err != nil {
		return "", err
	}

	return responseObject.Text, nil
}

func (sdk *AmazonPaySdk) GetRefundDetails(parameters map[string]interface{}) (string, error) {
	checkForRequiredParameters(parameters, paramsRefundDetails)

	params := map[string]interface{}{
		"Action": "GetRefundDetails",
	}

	fieldMappings := map[string]string{
		"merchant_id":     "SellerId",
		"amazon_refund_id": "AmazonRefundId",
	}

	responseObject, err := sdk.setParamsAndPost(params, fieldMappings, parameters)
	if err != nil {
		return "", err
	}

	return responseObject.Text, nil
}

func (sdk *AmazonPaySdk) ListOrderReference(parameters map[string]interface{}) (string, error) {
	checkForRequiredParameters(parameters, paramsListOrderReference)

	params := map[string]interface{}{
		"Action": "ListOrderReference",
	}

	fieldMappings := map[string]string{
		"merchant_id":                      "SellerId",
		"page_size":                       "PageSize",
		"payment_domain":                   "PaymentDomain",
		"query_id":                        "QueryId",
		"query_id_type":                    "QueryIdType",
		"sort_order":                       "SortOrder",
		"order_reference_status_list_filter": "OrderReferenceStatusListFilter.OrderReferenceStatus",
		"created_time_range_start":        "CreatedTimeRange.StartTime",
		"created_time_range_end":          "CreatedTimeRange.EndTime",
	}

	responseObject, err := sdk.setParamsAndPost(params, fieldMappings, parameters)
	if err != nil {
		return "", err
	}

	return responseObject.Text, nil
}

func (sdk *AmazonPaySdk) FetchTransactionDetails(parameters map[string]interface{}) (string, error) {
	obj := &FetchTransactionDetails{}
	return obj.FetchTransactionDetails(sdk, parameters)
}

func (sdk *AmazonPaySdk) setParamsAndPost(params, fieldMappings map[string]interface{}, requestParams map[string]interface{}) (*http.Response, error) {
	for param, value := range requestParams {
		if v, ok := value.(string); ok {
			requestParams[param] = strings.TrimSpace(v)
		}

		if mappedField, ok := fieldMappings[param]; ok && requestParams[param] != "" {
			if v, ok := requestParams[param].(map[string]interface{}); ok {
				for i := 1; i <= len(v); i++ {
					params[fmt.Sprintf("%s.%d", mappedField, i)] = v[fmt.Sprintf("%d", i-1)]
				}
			} else {
				params[mappedField] = requestParams[param]
			}
		}
	}

	params = sdk.setDefaultValues(params, fieldMappings, requestParams)
	params["Timestamp"] = time.Now().UTC().Format(dateTimeFormat)
	params["AWSAccessKeyId"] = sdk.AccessKey
	params["signatureMethod"] = "HmacSHA384"
	params["signatureVersion"] = 4

	serviceURL := fmt.Sprintf("https://%s%s", sdk.BaseURL, apiPath[params["Action"].(string)])
	delete(params, "Action")

	signature := sdk.getSignature(params, "GET", sdk.BaseURL)
	params["isSandbox"] = sdk.Sandbox
	paramsString := sdk.getParamsString(params)
	paramsString += "&Signature=" + url.QueryEscape(signature)

	headers := map[string]string{
		"x-amz-sdk-version": "Go-v1.0",
	}

	return sdk.invokeGet().Get(serviceURL + "?" + paramsString, headers)
}

func (sdk *AmazonPaySdk) invokeGet(retries int, backoffFactor float64, statusForcelist []int, session *http.Client) *http.Client {
	if session == nil {
		session = &http.Client{}
	}

	session.Transport = &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
	}

	return session
}

func (sdk *AmazonPaySdk) calculateSignForEncryption(params map[string]interface{}) map[string]interface{} {
	params["sellerId"] = sdk.MerchantID
	params["startTime"] = time.Now().Unix()
	return params
}

func (sdk *AmazonPaySdk) calculateSignForVerification(params map[string]interface{}) map[string]interface{} {
	return params
}

func (sdk *AmazonPaySdk) getSignature(params map[string]interface{}, method, endpoint string) string {
	return sdk.generateSignatures(params, method, endpoint, sdk.SecretKey)
}

func (sdk *AmazonPaySdk) generateSignatures(params map[string]interface{}, method, payHost, secretKey string) string {
	stringToSign := sdk.createStringToSign(params, "", "", method, payHost)
	signingKey := sdk.getSigningKey(secretKey, "", region, serviceName)
	signature := sdk.hmacSHA384(signingKey, []byte(stringToSign))
	return base64.URLEncoding.EncodeToString(signature)
}

func (sdk *AmazonPaySdk) createStringToSign(allParams map[string]interface{}, dateTimeStamp, dateStamp, method, payHost string) string {
	var stringToSign []string
	stringToSign = append(stringToSign, algorithm)
	stringToSign = append(stringToSign, newLineCharacter)
	stringToSign = append(stringToSign, dateTimeStamp)
	stringToSign = append(stringToSign, newLineCharacter)
	stringToSign = append(stringToSign, sdk.computeCredentialScope(dateStamp))
	stringToSign = append(stringToSign, newLineCharacter)
	stringToSign = append(stringToSign, sdk.getHashedCanonicalRequest(sdk.createCanonicalRequest(allParams, method, "https://"+payHost)))
	return strings.Join(stringToSign, "")
}

func (sdk *AmazonPaySdk) getSigningKey(key, dateStamp, regionName, serviceName string) []byte {
	kSecret := []byte("AWS4" + key)
	kDate := sdk.hmacSHA384(kSecret, []byte(dateStamp))
	kRegion := sdk.hmacSHA384(kDate, []byte(regionName))
	kService := sdk.hmacSHA384(kRegion, []byte(serviceName))
	kSigning := sdk.hmacSHA384(kService, []byte(terminationString))
	return kSigning
}

func (sdk *AmazonPaySdk) hmacSHA384(key, data []byte) []byte {
	h := hmac.New(sha384.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func (sdk *AmazonPaySdk) computeCredentialScope(dateStamp string) string {
	return fmt.Sprintf("%s/%s/%s/%s", dateStamp, region, serviceName, terminationString)
}

func (sdk *AmazonPaySdk) createCanonicalRequest(params map[string]interface{}, method, payHost string) string {
	var canonicalRequestString []string
	canonicalRequestString = append(canonicalRequestString, method)
	canonicalRequestString = append(canonicalRequestString, newLineCharacter)
	canonicalRequestString = append(canonicalRequestString, payHost+"/")
	canonicalRequestString = append(canonicalRequestString, newLineCharacter)
	canonicalRequestString = append(canonicalRequestString, sdk.formatParameters(params))
	return strings.Join(canonicalRequestString, "")
}

func (sdk *AmazonPaySdk) formatParameters(parameters map[string]interface{}) string {
	return sdk.formatAllParameters("", parameters)
}

func (sdk *AmazonPaySdk) formatAllParameters(initialQueryString string, parameters map[string]interface{}) string {
	if parameters == nil {
		return ""
	}

	var keys []string
	for k := range parameters {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var queryStringBuilder []string
	if initialQueryString != "" {
		queryStringBuilder = append(queryStringBuilder, initialQueryString)
		queryStringBuilder = append(queryStringBuilder, "&")
	}

	for i, key := range keys {
		value := parameters[key]
		encodedKey := sdk.percentEncodeRFC3986(fmt.Sprintf("%v", key))
		encodedValue := sdk.percentEncodeRFC3986(fmt.Sprintf("%v", value))
		queryStringBuilder = append(queryStringBuilder, fmt.Sprintf("%s=%s", encodedKey, encodedValue))
		if i < len(keys)-1 {
			queryStringBuilder = append(queryStringBuilder, "&")
		}
	}

	return strings.Join(queryStringBuilder, "")
}

func (sdk *AmazonPaySdk) percentEncodeRFC3986(s string) string {
	return url.QueryEscape(s)
}

func (sdk *AmazonPaySdk) getHashedCanonicalRequest(canonicalRequest string) string {
	digest := sha384.New()
	_, _ = digest.Write([]byte(canonicalRequest))
	return fmt.Sprintf("%x", digest.Sum(nil))
}

func (sdk *AmazonPaySdk) getParamsString(params map[string]interface{}) string {
	var pairs []string
	for k, v := range params {
		pairs = append(pairs, fmt.Sprintf("%s=%s", k, url.QueryEscape(fmt.Sprintf("%v", v))))
	}
	return strings.Join(pairs, "&")
}

func (sdk *AmazonPaySdk) aesGCMEncrypt(plaintext, key, iv []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	ciphertext := aesgcm.Seal(nil, iv, plaintext, nil)
	return ciphertext
}

func (sdk *AmazonPaySdk) rsaPublicEncrypt(plaintext []byte, publicKey []byte) []byte {
	pubkey, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		panic(err)
	}

	rsaPublicKey := pubkey.(*rsa.PublicKey)
	ciphertext, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, rsaPublicKey, plaintext, nil)
	if err != nil {
		panic(err)
	}

	return ciphertext
}

func checkForRequiredParameters(parameters, fields map[string]interface{}) {
	for fieldName, mandatory := range fields {
		if mandatory {
			_ = getMandatoryField(fieldName, parameters)
		} else {
			_ = getField(fieldName, parameters)
		}
	}

	for key := range parameters {
		if _, ok := fields[key]; !ok {
			panic(fmt.Errorf("error with json message - provided field %s should not be part of input", key))
		}
	}
}

func getMandatoryField(fieldName string, parameters map[string]interface{}) interface{} {
	value := getField(fieldName, parameters)
	if value == nil || value == "" {
		panic(fmt.Errorf("error with json message - mandatory field %s cannot be found or is empty", fieldName))
	}
	return value
}

func getField(fieldName string, parameters map[string]interface{}) interface{} {
	if value, ok := parameters[fieldName]; ok {
		return value
	}
	return nil
}

type FetchTransactionDetails struct{}

func (f *FetchTransactionDetails) FetchTransactionDetails(sdk *AmazonPaySdk, parameters map[string]interface{}) (string, error) {
	checkForRequiredParameters(parameters, paramsGetTransactionDetails)
	if parameters["transactionIdType"].(string) != "TRANSACTION_ID" {
		return "", fmt.Errorf("transaction type is not supported")
	}

	parameters["operationName"] = "SIGN_AND_ENCRYPT_GET_CHARGE_STATUS_REQUEST"
	getChargeStatusRequest, err := sdk.signAndEncryptParameters(parameters)
	if err != nil {
		return "", err
	}

	serviceURL := fmt.Sprintf("https://%s%s", sdk.BaseURL, apiPath["GetChargeStatus"])
	responseObject, err := sdk.invokeGet().Get(serviceURL+"?"+getChargeStatusRequest, nil)
	if err != nil {
		return "", err
	}

	return responseObject.Text, nil
}
}