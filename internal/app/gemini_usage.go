package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	geminiUsageRPC        = "jSf9Qc"
	geminiUsagePage       = "https://gemini.google.com/usage"
	geminiUsageRPCURL     = "https://gemini.google.com/_/BardChatUi/data/batchexecute"
	geminiUsageCacheTTL   = 30 * time.Second
	usagePercentTolerance = 1.5
)

var fdrFJeRe = regexp.MustCompile(`"FdrFJe":"([^"]{1,400})"`)

type geminiUsageWindow struct {
	UsedPercent      float64
	RemainingPercent float64
	ResetAt          time.Time
}

type geminiUsageSnapshot struct {
	AccountID    int64
	AccountLabel string
	Windows      map[int]geminiUsageWindow
	FetchedAt    time.Time
}

type geminiUsageError struct {
	Code       string
	Message    string
	HTTPStatus int
	Cause      error
}

func (e *geminiUsageError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

func (e *geminiUsageError) Unwrap() error { return e.Cause }

func newGeminiUsageAuthError(cause error) error {
	return &geminiUsageError{
		Code:    "auth_session_expired",
		Message: "Google session expired; re-login required",
		Cause:   cause,
	}
}

func newGeminiUsageProtocolError(message string, cause error) error {
	return &geminiUsageError{Code: "usage_protocol_error", Message: message, Cause: cause}
}

func geminiUsageHTTPError(status int) error {
	if status == 401 || status == 403 || status == 302 {
		return &geminiUsageError{
			Code:       "auth_session_expired",
			Message:    "Google session expired; re-login required",
			HTTPStatus: status,
		}
	}
	return &geminiUsageError{
		Code:       "usage_upstream_error",
		Message:    fmt.Sprintf("Gemini Apps usage RPC returned HTTP %d", status),
		HTTPStatus: status,
	}
}

type geminiUsagePageTokens struct {
	SNlM0e string
	Build  string
	FdrFJe string
}

// extractGeminiUsagePageTokens extracts only the page parameters needed by
// the consumer Gemini Apps usage RPC.  No extracted credential is ever logged.
func extractGeminiUsagePageTokens(body []byte) (geminiUsagePageTokens, error) {
	var out geminiUsagePageTokens
	if m := snlm0eRe.FindSubmatch(body); m != nil {
		out.SNlM0e = string(m[1])
	}
	if m := cfb2hRe.FindSubmatch(body); m != nil {
		out.Build = string(m[1])
	}
	if m := fdrFJeRe.FindSubmatch(body); m != nil {
		out.FdrFJe = string(m[1])
	}
	if out.SNlM0e == "" {
		return geminiUsagePageTokens{}, newGeminiUsageAuthError(errors.New("usage page has no SNlM0e"))
	}
	if out.Build == "" {
		return geminiUsagePageTokens{}, newGeminiUsageProtocolError("usage page has no cfb2h build label", nil)
	}
	return out, nil
}

var (
	geminiUsageCacheMu sync.Mutex
	geminiUsageCache   = map[int64]usageCacheEntry{}
	geminiUsageLocks   sync.Map // map[int64]*sync.Mutex
	geminiUsageFetcher = fetchGeminiUsageLive
)

type usageCacheEntry struct {
	snapshot  *geminiUsageSnapshot
	err       error
	fetchedAt time.Time
}

func invalidateGeminiUsageCache(accountID int64) {
	if accountID <= 0 {
		return
	}
	geminiUsageCacheMu.Lock()
	delete(geminiUsageCache, accountID)
	geminiUsageCacheMu.Unlock()
}

func geminiUsageAccountLock(accountID int64) *sync.Mutex {
	actual, _ := geminiUsageLocks.LoadOrStore(accountID, &sync.Mutex{})
	return actual.(*sync.Mutex)
}

func cachedGeminiUsage(a CookieAccount, force bool) (*geminiUsageSnapshot, error) {
	lock := geminiUsageAccountLock(a.ID)
	lock.Lock()
	defer lock.Unlock()

	if !force {
		geminiUsageCacheMu.Lock()
		entry, ok := geminiUsageCache[a.ID]
		geminiUsageCacheMu.Unlock()
		if ok && time.Since(entry.fetchedAt) < geminiUsageCacheTTL {
			return entry.snapshot, entry.err
		}
	}

	snapshot, err := geminiUsageFetcher(a)
	geminiUsageCacheMu.Lock()
	geminiUsageCache[a.ID] = usageCacheEntry{snapshot: snapshot, err: err, fetchedAt: time.Now()}
	geminiUsageCacheMu.Unlock()
	return snapshot, err
}

func fetchGeminiUsageLive(a CookieAccount) (*geminiUsageSnapshot, error) {
	// Usage is observational.  It may refresh the Google session cookie below,
	// but it must never call markCookieByStatus/markAccountResult: a quota probe
	// is not a model request and must not reorder, disable, or heal the routing
	// account pool.
	picked, ok, err := acquireSlot(a.ProxyID)
	if !ok {
		return nil, err
	}
	defer releaseSlot(picked.ID)
	proxyURL := picked.URL

	page, err := fetchAppPage(a.Cookie, proxyURL)
	if err != nil {
		if isGeminiUsageAuthFailure(err) {
			return nil, newGeminiUsageAuthError(err)
		}
		return nil, err
	}
	tokens, err := extractGeminiUsagePageTokens(page)
	if err != nil {
		return nil, err
	}

	query := url.Values{}
	query.Set("rpcids", geminiUsageRPC)
	query.Set("source-path", "/usage")
	query.Set("bl", tokens.Build)
	query.Set("hl", "en")
	query.Set("rt", "c")
	query.Set("_reqid", strconv.FormatInt(time.Now().Unix()%1000000, 10))
	if tokens.FdrFJe != "" {
		// The current usage page may require the page session id.  It is
		// optional in observed deployments, so only send it when present.
		query.Set("f.sid", tokens.FdrFJe)
	}
	endpoint := geminiUsageRPCURL + "?" + query.Encode()

	form := url.Values{}
	form.Set("at", tokens.SNlM0e)
	// The second element is deliberately a JSON string containing [] rather
	// than a nested JSON array.  This is the batchexecute contract.
	form.Set("f.req", `[[["jSf9Qc","[]",null,"generic"]]]`)
	headers := buildGeminiHeaders(a.Cookie, extractSAPISID(a.Cookie), "")
	headers["Referer"] = geminiUsagePage

	status, raw, _, setCookie, err := doGeminiRequest(endpoint, form.Encode(), headers, proxyURL, nil)
	if len(setCookie) > 0 {
		merged := mergeSetCookie(a.Cookie, setCookie)
		if merged != a.Cookie {
			updateAccountCookie(a.ID, merged)
		}
	}
	if err != nil {
		return nil, err
	}
	if status == 401 || status == 403 || status == 302 {
		return nil, geminiUsageHTTPError(status)
	}
	if status != 200 {
		return nil, geminiUsageHTTPError(status)
	}

	windows, err := parseGeminiUsageRPC(raw)
	if err != nil {
		// Only report structure, lengths, and scalar kinds in debug output.
		logf("[gemini-usage] account #%d parse failed: %v shape=%s", a.ID, err, usageShape(raw))
		return nil, newGeminiUsageProtocolError("Gemini Apps usage response could not be parsed", err)
	}
	return &geminiUsageSnapshot{
		AccountID:    a.ID,
		AccountLabel: a.Label,
		Windows:      windows,
		FetchedAt:    time.Now().UTC(),
	}, nil
}

func isGeminiUsageAuthFailure(err error) bool {
	if err == nil {
		return false
	}
	var usageErr *geminiUsageError
	if errors.As(err, &usageErr) {
		return usageErr.Code == "auth_session_expired"
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "http 401") || strings.Contains(msg, "http 403") ||
		strings.Contains(msg, "http 302") || strings.Contains(msg, "no snlm0e")
}

func geminiUsageWindowsJSON(windows map[int]geminiUsageWindow) map[string]interface{} {
	out := map[string]interface{}{}
	for typ, name := range map[int]string{1: "five_hour", 2: "weekly"} {
		w, ok := windows[typ]
		if !ok {
			continue
		}
		out[name] = map[string]interface{}{
			"used_percent":      w.UsedPercent,
			"remaining_percent": w.RemainingPercent,
			"reset_at":          w.ResetAt.UTC().Format(time.RFC3339),
		}
	}
	return out
}

func geminiUsageErrorJSON(err error) map[string]interface{} {
	var usageErr *geminiUsageError
	if errors.As(err, &usageErr) {
		return map[string]interface{}{"code": usageErr.Code, "message": usageErr.Message}
	}
	return map[string]interface{}{"code": "usage_unavailable", "message": "Gemini Apps usage is temporarily unavailable"}
}

func geminiUsageItem(a CookieAccount, force bool) map[string]interface{} {
	item := map[string]interface{}{
		"account": map[string]interface{}{"id": a.ID, "label": a.Label},
	}
	if a.Status != "enabled" {
		item["status"] = "disabled"
		return item
	}
	snapshot, err := cachedGeminiUsage(a, force)
	if err != nil {
		var usageErr *geminiUsageError
		if errors.As(err, &usageErr) {
			item["status"] = usageErr.Code
		} else {
			item["status"] = "unavailable"
		}
		item["error"] = geminiUsageErrorJSON(err)
		return item
	}
	item["status"] = "ok"
	item["windows"] = geminiUsageWindowsJSON(snapshot.Windows)
	item["fetched_at"] = snapshot.FetchedAt.UTC().Format(time.RFC3339)
	return item
}

func usageAccountByQuery(r *http.Request) (*CookieAccount, error) {
	raw := strings.TrimSpace(r.URL.Query().Get("account_id"))
	if raw == "" {
		return nil, nil
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		return nil, errors.New("account_id must be a positive integer")
	}
	a := accountByID(id)
	if a == nil {
		return nil, errors.New("account not found")
	}
	return a, nil
}

// handleGeminiUsage serves the machine-facing Gemini Apps consumer quota API.
// It is intentionally separate from any Gemini CLI, Code Assist, or
// Antigravity quota surface.
func handleGeminiUsage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, 405, map[string]string{"error": "method not allowed"})
		return
	}
	a, err := usageAccountByQuery(r)
	if err != nil {
		status := 404
		if strings.Contains(err.Error(), "account_id must") {
			status = 400
		}
		writeJSON(w, status, map[string]interface{}{"error": map[string]string{"code": "bad_account", "message": err.Error()}})
		return
	}
	if a != nil {
		if a.Status != "enabled" {
			writeJSON(w, 409, map[string]interface{}{"error": map[string]string{"code": "account_disabled", "message": "Google account is disabled"}})
			return
		}
		item := geminiUsageItem(*a, false)
		if item["status"] != "ok" {
			code := 502
			if item["status"] == "auth_session_expired" {
				code = 401
			}
			writeJSON(w, code, map[string]interface{}{
				"object":  "gemini.usage",
				"source":  "gemini_apps_web",
				"account": item["account"],
				"status":  item["status"],
				"error":   item["error"],
			})
			return
		}
		writeJSON(w, 200, map[string]interface{}{
			"object":     "gemini.usage",
			"source":     "gemini_apps_web",
			"account":    item["account"],
			"windows":    item["windows"],
			"fetched_at": item["fetched_at"],
		})
		return
	}

	var enabled []CookieAccount
	for _, item := range accountList() {
		if item.Status == "enabled" {
			enabled = append(enabled, item)
		}
	}
	if len(enabled) == 0 {
		writeJSON(w, 404, map[string]interface{}{"error": map[string]string{
			"code": "no_enabled_google_account", "message": "no enabled Google account is available",
		}})
		return
	}
	if len(enabled) == 1 {
		item := geminiUsageItem(enabled[0], false)
		if item["status"] != "ok" {
			code := 502
			if item["status"] == "auth_session_expired" {
				code = 401
			}
			writeJSON(w, code, map[string]interface{}{
				"object": "gemini.usage", "source": "gemini_apps_web", "account": item["account"],
				"status": item["status"], "error": item["error"],
			})
			return
		}
		writeJSON(w, 200, map[string]interface{}{
			"object": "gemini.usage", "source": "gemini_apps_web", "account": item["account"],
			"windows": item["windows"], "fetched_at": item["fetched_at"],
		})
		return
	}
	items := make([]map[string]interface{}, 0, len(enabled))
	for _, item := range enabled {
		items = append(items, geminiUsageItem(item, false))
	}
	writeJSON(w, 200, map[string]interface{}{
		"object": "list", "source": "gemini_apps_web", "accounts": items,
	})
}

// handleAdminGeminiUsage returns one item per account so an expired account
// does not hide healthy accounts from the dashboard.
func handleAdminGeminiUsage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, 405, map[string]string{"error": "method not allowed"})
		return
	}
	force := r.URL.Query().Get("refresh") == "1"
	if a, err := usageAccountByQuery(r); err != nil {
		status := 404
		if strings.Contains(err.Error(), "account_id must") {
			status = 400
		}
		writeJSON(w, status, map[string]interface{}{"error": map[string]string{"code": "bad_account", "message": err.Error()}})
		return
	} else if a != nil {
		writeJSON(w, 200, map[string]interface{}{
			"object": "gemini.usage.list", "source": "gemini_apps_web",
			"items": []map[string]interface{}{geminiUsageItem(*a, force)},
		})
		return
	}
	items := accountList()
	out := make([]map[string]interface{}, 0, len(items))
	for _, item := range items {
		out = append(out, geminiUsageItem(item, force))
	}
	writeJSON(w, 200, map[string]interface{}{
		"object": "gemini.usage.list", "source": "gemini_apps_web", "items": out,
	})
}

// parseGeminiUsageRPC parses the length-prefixed batchexecute response and
// searches structurally for the window list.  It never uses array order to
// assign five-hour versus weekly; only the explicit type code is accepted.
func parseGeminiUsageRPC(raw []byte) (map[int]geminiUsageWindow, error) {
	frames, err := decodeGeminiRPCFrames(raw)
	if err != nil {
		return nil, err
	}
	var found map[int]geminiUsageWindow
	var candidateErr error
	var walk func(interface{})
	walk = func(node interface{}) {
		if found != nil {
			return
		}
		switch v := node.(type) {
		case []interface{}:
			if schema, windows, ok := usageWindowListCandidate(v); ok {
				parsed, err := parseGeminiUsageWindowList(schema, windows)
				if err == nil {
					found = parsed
					return
				}
				candidateErr = err
			}
			for _, child := range v {
				walk(child)
			}
		case string:
			trimmed := strings.TrimSpace(v)
			if trimmed == "" || (trimmed[0] != '[' && trimmed[0] != '{') {
				return
			}
			var nested interface{}
			if json.Unmarshal([]byte(trimmed), &nested) == nil {
				walk(nested)
			}
		case map[string]interface{}:
			for _, child := range v {
				walk(child)
			}
		}
	}
	for _, frame := range frames {
		walk(frame)
	}
	if found != nil {
		return found, nil
	}
	if candidateErr != nil {
		return nil, candidateErr
	}
	return nil, errors.New("no recognized Gemini Apps usage window list")
}

const (
	usageSchemaA = 1
	usageSchemaB = 2
)

func usageWindowListCandidate(arr []interface{}) (int, [][]interface{}, bool) {
	var schema int
	var windows [][]interface{}
	for _, item := range arr {
		if item == nil {
			continue
		}
		w, ok := item.([]interface{})
		if !ok {
			return 0, nil, false
		}
		shape := usageWindowShape(w)
		if shape == 0 {
			return 0, nil, false
		}
		if schema == 0 {
			schema = shape
		} else if schema != shape {
			return 0, nil, false
		}
		windows = append(windows, w)
	}
	return schema, windows, len(windows) > 0
}

func usageWindowShape(w []interface{}) int {
	if len(w) >= 8 && usageNumberAt(w, 4) && usageTimestampArray(w[5]) &&
		usageNullableAt(w, 6) && usageNullableAt(w, 7) {
		return usageSchemaB
	}
	if len(w) >= 4 && usageNullableNumber(w[1]) && usageNumberAt(w, 2) && usageSchemaAReset(w[3]) {
		return usageSchemaA
	}
	return 0
}

func parseGeminiUsageWindowList(schema int, windows [][]interface{}) (map[int]geminiUsageWindow, error) {
	out := map[int]geminiUsageWindow{}
	for _, w := range windows {
		var typ float64
		var used, remaining *float64
		var reset time.Time
		var err error
		switch schema {
		case usageSchemaA:
			typ, _ = usageNumber(w[2])
			if f, ok := usageNumber(w[1]); ok {
				used = ptrFloat(f * 100)
			}
			reset, err = parseSchemaAReset(w[3])
		case usageSchemaB:
			typ, _ = usageNumber(w[4])
			if f, ok := usageNumber(usageValueAt(w, 6)); ok {
				used = ptrFloat(f)
			}
			if f, ok := usageNumber(usageValueAt(w, 7)); ok {
				remaining = ptrFloat(f)
			}
			reset, err = parseTimestampArray(w[5])
		default:
			return nil, errors.New("unknown usage schema")
		}
		if err != nil {
			return nil, err
		}
		typeCode := int(typ)
		if typ != float64(typeCode) || (typeCode != 1 && typeCode != 2) {
			return nil, fmt.Errorf("unknown usage window type %v", typ)
		}
		if schema == usageSchemaA {
			if used == nil {
				return nil, errors.New("schema A window is missing used fraction")
			}
			remaining = ptrFloat(100 - *used)
		}
		used, remaining, err = completeUsagePercentages(used, remaining)
		if err != nil {
			return nil, err
		}
		if _, exists := out[typeCode]; exists {
			return nil, fmt.Errorf("duplicate usage window type %d", typeCode)
		}
		out[typeCode] = geminiUsageWindow{UsedPercent: *used, RemainingPercent: *remaining, ResetAt: reset}
	}
	if _, ok := out[1]; !ok {
		return nil, errors.New("usage response is missing five-hour window")
	}
	if _, ok := out[2]; !ok {
		return nil, errors.New("usage response is missing weekly window")
	}
	return out, nil
}

func completeUsagePercentages(used, remaining *float64) (*float64, *float64, error) {
	if used == nil && remaining == nil {
		return nil, nil, errors.New("usage window has neither used nor remaining percentage")
	}
	if used != nil && (*used < 0 || *used > 100) {
		return nil, nil, errors.New("used percentage is outside 0..100")
	}
	if remaining != nil && (*remaining < 0 || *remaining > 100) {
		return nil, nil, errors.New("remaining percentage is outside 0..100")
	}
	if used == nil {
		used = ptrFloat(100 - *remaining)
	}
	if remaining == nil {
		remaining = ptrFloat(100 - *used)
	}
	if math.Abs(*used+*remaining-100) > usagePercentTolerance {
		return nil, nil, fmt.Errorf("used and remaining percentages do not add to 100")
	}
	return used, remaining, nil
}

func ptrFloat(v float64) *float64 { return &v }

func usageNumberAt(v []interface{}, index int) bool {
	if index < 0 || index >= len(v) {
		return false
	}
	_, ok := usageNumber(v[index])
	return ok
}

func usageNullableNumber(v interface{}) bool {
	if v == nil {
		return true
	}
	_, ok := usageNumber(v)
	return ok
}

func usageNullableAt(v []interface{}, index int) bool {
	return usageNullableNumber(usageValueAt(v, index))
}

func usageValueAt(v []interface{}, index int) interface{} {
	if index < 0 || index >= len(v) {
		return nil
	}
	return v[index]
}

func usageNumber(v interface{}) (float64, bool) {
	f, ok := v.(float64)
	return f, ok && !math.IsNaN(f) && !math.IsInf(f, 0)
}

func usageTimestampArray(v interface{}) bool {
	arr, ok := v.([]interface{})
	return ok && len(arr) >= 1 && usageNumberAt(arr, 0)
}

func usageSchemaAReset(v interface{}) bool {
	outer, ok := v.([]interface{})
	if !ok || len(outer) == 0 {
		return false
	}
	inner, ok := outer[0].([]interface{})
	return ok && len(inner) > 0 && usageNumberAt(inner, 0)
}

func parseTimestampArray(v interface{}) (time.Time, error) {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return time.Time{}, errors.New("usage window reset timestamp is malformed")
	}
	seconds, ok := usageNumber(arr[0])
	if !ok || seconds <= 0 {
		return time.Time{}, errors.New("usage window reset timestamp is invalid")
	}
	nanos := int64(0)
	if len(arr) > 1 {
		if n, ok := usageNumber(arr[1]); ok && n >= 0 && n < 1e9 {
			nanos = int64(n)
		}
	}
	return time.Unix(int64(seconds), nanos).UTC(), nil
}

func parseSchemaAReset(v interface{}) (time.Time, error) {
	outer, ok := v.([]interface{})
	if !ok || len(outer) == 0 {
		return time.Time{}, errors.New("schema A reset timestamp is malformed")
	}
	inner, ok := outer[0].([]interface{})
	if !ok || len(inner) == 0 {
		return time.Time{}, errors.New("schema A reset timestamp is malformed")
	}
	seconds, ok := usageNumber(inner[0])
	if !ok || seconds <= 0 {
		return time.Time{}, errors.New("schema A reset timestamp is invalid")
	}
	return time.Unix(int64(seconds), 0).UTC(), nil
}

// decodeGeminiRPCFrames accepts both Google's length-prefixed framing and the
// single-frame form used by small fixtures.  json.Decoder finds the end of a
// frame without trusting the advertised length (which is UTF-16 based).
func decodeGeminiRPCFrames(raw []byte) ([]interface{}, error) {
	s := strings.TrimSpace(string(raw))
	if strings.HasPrefix(s, ")]}'") {
		s = strings.TrimSpace(s[4:])
	}
	if s == "" {
		return nil, errors.New("empty RPC response")
	}
	var frames []interface{}
	for strings.TrimSpace(s) != "" {
		s = strings.TrimSpace(s)
		if s[0] != '[' && s[0] != '{' {
			lineEnd := strings.IndexByte(s, '\n')
			if lineEnd <= 0 {
				return nil, errors.New("malformed length-prefixed RPC envelope")
			}
			if _, err := strconv.Atoi(strings.TrimSpace(s[:lineEnd])); err != nil {
				return nil, errors.New("malformed RPC frame length")
			}
			s = s[lineEnd+1:]
			s = strings.TrimLeft(s, " \t\r\n")
			if s == "" {
				return nil, errors.New("RPC frame has no JSON payload")
			}
		}
		decoder := json.NewDecoder(strings.NewReader(s))
		var frame interface{}
		if err := decoder.Decode(&frame); err != nil {
			return nil, fmt.Errorf("decode RPC frame: %w", err)
		}
		if _, ok := frame.([]interface{}); !ok {
			return nil, errors.New("RPC frame is not an array")
		}
		frames = append(frames, frame)
		consumed := int(decoder.InputOffset())
		if consumed <= 0 || consumed > len(s) {
			return nil, errors.New("invalid RPC frame boundary")
		}
		s = s[consumed:]
	}
	return frames, nil
}

// usageShape intentionally discards values and strings.  It is safe to use in
// debug logs even when called with a response containing session material.
func usageShape(raw []byte) string {
	frames, err := decodeGeminiRPCFrames(raw)
	if err != nil {
		return "invalid-envelope"
	}
	var shape func(interface{}, int) string
	shape = func(v interface{}, depth int) string {
		if depth > 6 {
			return "…"
		}
		switch x := v.(type) {
		case nil:
			return "null"
		case string:
			return "string"
		case float64:
			return "number"
		case []interface{}:
			parts := make([]string, 0, minInt(len(x), 8))
			for i, child := range x {
				if i >= 8 {
					break
				}
				parts = append(parts, shape(child, depth+1))
			}
			return "[" + strings.Join(parts, ",") + "]"
		case map[string]interface{}:
			keys := make([]string, 0, len(x))
			for key := range x {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			if len(keys) > 8 {
				keys = keys[:8]
			}
			return "{" + strings.Join(keys, ",") + "}"
		default:
			return "other"
		}
	}
	parts := make([]string, 0, len(frames))
	for _, frame := range frames {
		parts = append(parts, shape(frame, 0))
	}
	return strings.Join(parts, "|")
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
