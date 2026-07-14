package handles

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/alist-org/alist/v3/internal/op"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/Xhofe/go-cache"

	"github.com/alist-org/alist/v3/internal/conf"
	"github.com/alist-org/alist/v3/internal/db"
	"github.com/alist-org/alist/v3/internal/model"
	"github.com/alist-org/alist/v3/internal/setting"
	"github.com/alist-org/alist/v3/pkg/utils"
	"github.com/alist-org/alist/v3/pkg/utils/random"
	"github.com/alist-org/alist/v3/server/common"
	"github.com/coreos/go-oidc"
	"github.com/gin-gonic/gin"
	"github.com/go-resty/resty/v2"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
)

const stateLength = 16
const stateExpire = time.Minute * 5

var stateCache = cache.NewMemCache[string](cache.WithShards[string](stateLength))

func _keyState(clientID, state string) string {
	return fmt.Sprintf("%s_%s", clientID, state)
}

func generateState(clientID, ip string) string {
	state := random.String(stateLength)
	stateCache.Set(_keyState(clientID, state), ip, cache.WithEx[string](stateExpire))
	return state
}

func verifyState(clientID, ip, state string) bool {
	value, ok := stateCache.Get(_keyState(clientID, state))
	return ok && value == ip
}

func ssoRedirectUri(c *gin.Context, useCompatibility bool, method string) string {
	if useCompatibility {
		return common.GetApiUrl(c.Request) + "/api/auth/" + method
	} else {
		return common.GetApiUrl(c.Request) + "/api/auth/sso_callback" + "?method=" + method
	}
}

func SSOLoginRedirect(c *gin.Context) {
	method := c.Query("method")
	useCompatibility := setting.GetBool(conf.SSOCompatibilityMode)
	enabled := setting.GetBool(conf.SSOLoginEnabled)
	clientId := setting.GetStr(conf.SSOClientId)
	platform := setting.GetStr(conf.SSOLoginPlatform)
	var rUrl string
	if !enabled {
		common.ErrorStrResp(c, "Single sign-on is not enabled", 403)
		return
	}
	urlValues := url.Values{}
	if method == "" {
		common.ErrorStrResp(c, "no method provided", 400)
		return
	}
	redirectUri := ssoRedirectUri(c, useCompatibility, method)
	urlValues.Add("response_type", "code")
	urlValues.Add("redirect_uri", redirectUri)
	urlValues.Add("client_id", clientId)
	switch platform {
	case "Github":
		rUrl = "https://github.com/login/oauth/authorize?"
		urlValues.Add("scope", "read:user")
	case "Microsoft":
		rUrl = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?"
		urlValues.Add("scope", "user.read")
		urlValues.Add("response_mode", "query")
	case "Google":
		rUrl = "https://accounts.google.com/o/oauth2/v2/auth?"
		urlValues.Add("scope", "https://www.googleapis.com/auth/userinfo.profile")
	case "Dingtalk":
		rUrl = "https://login.dingtalk.com/oauth2/auth?"
		urlValues.Add("scope", "openid")
		urlValues.Add("prompt", "consent")
		urlValues.Add("response_type", "code")
	case "Feishu":
		// Feishu's legacy passport endpoints have been deprecated. The current
		// OAuth flow starts at accounts.feishu.cn and returns the state verbatim.
		// Keep state server-side so the callback cannot be replayed or initiated
		// by a different browser.
		rUrl = "https://accounts.feishu.cn/open-apis/authen/v1/authorize?"
		urlValues.Add("state", generateState(clientId, c.ClientIP()))
	case "Casdoor":
		endpoint := strings.TrimSuffix(setting.GetStr(conf.SSOEndpointName), "/")
		rUrl = endpoint + "/login/oauth/authorize?"
		urlValues.Add("scope", "profile")
		urlValues.Add("state", endpoint)
	case "OIDC":
		oauth2Config, err := GetOIDCClient(c, useCompatibility, redirectUri, method)
		if err != nil {
			common.ErrorStrResp(c, err.Error(), 400)
			return
		}
		state := generateState(clientId, c.ClientIP())
		c.Redirect(http.StatusFound, oauth2Config.AuthCodeURL(state))
		return
	default:
		common.ErrorStrResp(c, "invalid platform", 400)
		return
	}
	c.Redirect(302, rUrl+urlValues.Encode())
}

var ssoClient = resty.New().SetRetryCount(3)

func GetOIDCClient(c *gin.Context, useCompatibility bool, redirectUri, method string) (*oauth2.Config, error) {
	if redirectUri == "" {
		redirectUri = ssoRedirectUri(c, useCompatibility, method)
	}
	endpoint := setting.GetStr(conf.SSOEndpointName)
	provider, err := oidc.NewProvider(c, endpoint)
	if err != nil {
		return nil, err
	}
	clientId := setting.GetStr(conf.SSOClientId)
	clientSecret := setting.GetStr(conf.SSOClientSecret)
	extraScopes := []string{}
	if setting.GetStr(conf.SSOExtraScopes) != "" {
		extraScopes = strings.Split(setting.GetStr(conf.SSOExtraScopes), " ")
	}
	return &oauth2.Config{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		RedirectURL:  redirectUri,

		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: append([]string{oidc.ScopeOpenID, "profile"}, extraScopes...),
	}, nil
}

func autoRegister(username, userID string, err error) (*model.User, error) {
	if !errors.Is(err, gorm.ErrRecordNotFound) || !setting.GetBool(conf.SSOAutoRegister) {
		return nil, err
	}
	if username == "" {
		return nil, errors.New("cannot get username from SSO provider")
	}
	defaultRoleID := op.GetDefaultRoleID()
	defaultRole, err := op.GetRole(uint(defaultRoleID))
	if err != nil {
		return nil, fmt.Errorf("cannot load default role for SSO auto-registration: %w", err)
	}
	if defaultRole.Name == "guest" || defaultRole.Name == "admin" {
		return nil, errors.New("SSO auto-registration requires a non-guest, non-admin default role")
	}
	user := &model.User{
		ID:         0,
		Username:   username,
		Password:   random.String(16),
		Permission: int32(setting.GetInt(conf.SSODefaultPermission, 0)),
		BasePath:   setting.GetStr(conf.SSODefaultDir),
		Role:       model.Roles{defaultRoleID},
		Disabled:   false,
		SsoID:      userID,
	}
	if err = db.CreateUser(user); err != nil {
		if strings.HasPrefix(err.Error(), "UNIQUE constraint failed") && strings.HasSuffix(err.Error(), "username") {
			user.Username = user.Username + "_" + userID
			if err = db.CreateUser(user); err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	return user, nil
}

func parseJWT(p string) ([]byte, error) {
	parts := strings.Split(p, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("oidc: malformed jwt, expected 3 parts got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("oidc: malformed jwt payload: %v", err)
	}
	return payload, nil
}

func OIDCLoginCallback(c *gin.Context) {
	useCompatibility := setting.GetBool(conf.SSOCompatibilityMode)
	method := c.Query("method")
	if useCompatibility {
		method = path.Base(c.Request.URL.Path)
	}
	clientId := setting.GetStr(conf.SSOClientId)
	endpoint := setting.GetStr(conf.SSOEndpointName)
	provider, err := oidc.NewProvider(c, endpoint)
	if err != nil {
		common.ErrorResp(c, err, 400)
		return
	}
	oauth2Config, err := GetOIDCClient(c, useCompatibility, "", method)
	if err != nil {
		common.ErrorResp(c, err, 400)
		return
	}
	if !verifyState(clientId, c.ClientIP(), c.Query("state")) {
		common.ErrorStrResp(c, "incorrect or expired state parameter", 400)
		return
	}

	oauth2Token, err := oauth2Config.Exchange(c, c.Query("code"))
	if err != nil {
		common.ErrorResp(c, err, 400)
		return
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		common.ErrorStrResp(c, "no id_token found in oauth2 token", 400)
		return
	}
	verifier := provider.Verifier(&oidc.Config{
		ClientID: clientId,
	})
	_, err = verifier.Verify(c, rawIDToken)
	if err != nil {
		common.ErrorResp(c, err, 400)
		return
	}
	payload, err := parseJWT(rawIDToken)
	if err != nil {
		common.ErrorResp(c, err, 400)
		return
	}
	userID := utils.Json.Get(payload, setting.GetStr(conf.SSOOIDCUsernameKey, "name")).ToString()
	if userID == "" {
		common.ErrorStrResp(c, "cannot get username from OIDC provider", 400)
		return
	}
	if method == "get_sso_id" {
		if useCompatibility {
			c.Redirect(302, common.GetApiUrl(c.Request)+"/@manage?sso_id="+userID)
			return
		}
		html := fmt.Sprintf(`<!DOCTYPE html>
				<head></head>
				<body>
				<script>
				window.opener.postMessage({"sso_id": "%s"}, "*")
				window.close()
				</script>
				</body>`, userID)
		c.Data(200, "text/html; charset=utf-8", []byte(html))
		return
	}
	if method == "sso_get_token" {
		user, err := db.GetUserBySSOID(userID)
		if err != nil {
			user, err = autoRegister(userID, userID, err)
			if err != nil {
				common.ErrorResp(c, err, 400)
				return
			}
		}
		token, err := common.GenerateToken(user)
		if err != nil {
			common.ErrorResp(c, err, 400)
		}
		if useCompatibility {
			c.Redirect(302, common.GetApiUrl(c.Request)+"/@login?token="+token)
			return
		}
		html := fmt.Sprintf(`<!DOCTYPE html>
				<head></head>
				<body>
				<script>
				window.opener.postMessage({"token":"%s"}, "*")
				window.close()
				</script>
				</body>`, token)
		c.Data(200, "text/html; charset=utf-8", []byte(html))
		return
	}
}

func SSOLoginCallback(c *gin.Context) {
	enabled := setting.GetBool(conf.SSOLoginEnabled)
	usecompatibility := setting.GetBool(conf.SSOCompatibilityMode)
	if !enabled {
		common.ErrorResp(c, errors.New("sso login is disabled"), 500)
		return
	}
	argument := c.Query("method")
	if usecompatibility {
		argument = path.Base(c.Request.URL.Path)
	}
	if !utils.SliceContains([]string{"get_sso_id", "sso_get_token"}, argument) {
		common.ErrorResp(c, errors.New("invalid request"), 500)
		return
	}
	clientId := setting.GetStr(conf.SSOClientId)
	platform := setting.GetStr(conf.SSOLoginPlatform)
	clientSecret := setting.GetStr(conf.SSOClientSecret)
	var tokenUrl, userUrl, scope, authField, idField, usernameField string
	additionalForm := make(map[string]string)
	switch platform {
	case "Github":
		tokenUrl = "https://github.com/login/oauth/access_token"
		userUrl = "https://api.github.com/user"
		authField = "code"
		scope = "read:user"
		idField = "id"
		usernameField = "login"
	case "Microsoft":
		tokenUrl = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
		userUrl = "https://graph.microsoft.com/v1.0/me"
		additionalForm["grant_type"] = "authorization_code"
		scope = "user.read"
		authField = "code"
		idField = "id"
		usernameField = "displayName"
	case "Google":
		tokenUrl = "https://oauth2.googleapis.com/token"
		userUrl = "https://www.googleapis.com/oauth2/v1/userinfo"
		additionalForm["grant_type"] = "authorization_code"
		scope = "https://www.googleapis.com/auth/userinfo.profile"
		authField = "code"
		idField = "id"
		usernameField = "name"
	case "Dingtalk":
		tokenUrl = "https://api.dingtalk.com/v1.0/oauth2/userAccessToken"
		userUrl = "https://api.dingtalk.com/v1.0/contact/users/me"
		authField = "authCode"
		idField = "unionId"
		usernameField = "nick"
	case "Feishu":
		tokenUrl = "https://open.feishu.cn/open-apis/authen/v2/oauth/token"
		userUrl = "https://open.feishu.cn/open-apis/authen/v1/user_info"
		additionalForm["grant_type"] = "authorization_code"
		authField = "code"
		idField = "open_id"
		usernameField = "name"
	case "Casdoor":
		endpoint := strings.TrimSuffix(setting.GetStr(conf.SSOEndpointName), "/")
		tokenUrl = endpoint + "/api/login/oauth/access_token"
		userUrl = endpoint + "/api/userinfo"
		additionalForm["grant_type"] = "authorization_code"
		scope = "profile"
		authField = "code"
		idField = "sub"
		usernameField = "preferred_username"
	case "OIDC":
		OIDCLoginCallback(c)
		return
	default:
		common.ErrorStrResp(c, "invalid platform", 400)
		return
	}
	callbackCode := c.Query(authField)
	if callbackCode == "" {
		if platform == "Feishu" && c.Query("error") != "" {
			log.Warnf("Feishu SSO authorization callback returned error=%q", c.Query("error"))
			common.ErrorStrResp(c, "Feishu authorization failed: "+c.Query("error"), 400)
			return
		}
		common.ErrorStrResp(c, "No code provided", 400)
		return
	}
	if platform == "Feishu" && !verifyState(clientId, c.ClientIP(), c.Query("state")) {
		log.Warn("Feishu SSO callback rejected because state is missing, expired, or does not match")
		common.ErrorStrResp(c, "incorrect or expired state parameter", 400)
		return
	}
	redirectURI := ssoRedirectUri(c, usecompatibility, argument)
	var resp *resty.Response
	var err error
	if platform == "Dingtalk" {
		resp, err = ssoClient.R().SetHeader("content-type", "application/json").SetHeader("Accept", "application/json").
			SetBody(map[string]string{
				"clientId":     clientId,
				"clientSecret": clientSecret,
				"code":         callbackCode,
				"grantType":    "authorization_code",
			}).
			Post(tokenUrl)
	} else if platform == "Feishu" {
		// The current Feishu token endpoint accepts a JSON request body. The
		// legacy endpoint accepted a form body, which is why the old integration
		// reached the callback but never produced a usable AList login token.
		resp, err = ssoClient.R().SetHeader("Content-Type", "application/json; charset=utf-8").
			SetHeader("Accept", "application/json").
			SetBody(map[string]string{
				"grant_type":    "authorization_code",
				"client_id":     clientId,
				"client_secret": clientSecret,
				"code":          callbackCode,
				"redirect_uri":  redirectURI,
			}).Post(tokenUrl)
	} else {
		resp, err = ssoClient.R().SetHeader("Accept", "application/json").
			SetFormData(map[string]string{
				"client_id":     clientId,
				"client_secret": clientSecret,
				"code":          callbackCode,
				"redirect_uri":  redirectURI,
				"scope":         scope,
			}).SetFormData(additionalForm).Post(tokenUrl)
	}
	if err != nil {
		if platform == "Feishu" {
			log.Errorf("Feishu SSO token exchange request failed: %v", err)
		}
		common.ErrorResp(c, err, 400)
		return
	}
	if resp.IsError() {
		if platform == "Feishu" {
			log.Errorf("Feishu SSO token exchange returned HTTP %s", resp.Status())
		}
		common.ErrorStrResp(c, fmt.Sprintf("SSO token exchange failed: %s", resp.Status()), 400)
		return
	}
	if platform == "Feishu" && utils.Json.Get(resp.Body(), "code").ToInt() != 0 {
		log.Errorf("Feishu SSO token exchange failed: api_code=%d message=%q", utils.Json.Get(resp.Body(), "code").ToInt(), utils.Json.Get(resp.Body(), "msg").ToString())
		common.ErrorStrResp(c, "Feishu token exchange failed: "+utils.Json.Get(resp.Body(), "msg").ToString(), 400)
		return
	}
	if platform == "Dingtalk" {
		accessToken := utils.Json.Get(resp.Body(), "accessToken").ToString()
		resp, err = ssoClient.R().SetHeader("x-acs-dingtalk-access-token", accessToken).
			Get(userUrl)
	} else {
		accessToken := utils.Json.Get(resp.Body(), "access_token").ToString()
		if platform == "Feishu" && accessToken == "" {
			log.Error("Feishu SSO token exchange succeeded without an access_token")
			common.ErrorStrResp(c, "Feishu token exchange did not return an access token", 400)
			return
		}
		userInfoRequest := ssoClient.R().SetHeader("Authorization", "Bearer "+accessToken)
		if platform == "Feishu" {
			userInfoRequest.SetHeader("Content-Type", "application/json; charset=utf-8")
		}
		resp, err = userInfoRequest.
			Get(userUrl)
	}
	if err != nil {
		if platform == "Feishu" {
			log.Errorf("Feishu SSO user-info request failed: %v", err)
		}
		common.ErrorResp(c, err, 400)
		return
	}
	if resp.IsError() {
		if platform == "Feishu" {
			log.Errorf("Feishu SSO user-info request returned HTTP %s", resp.Status())
		}
		common.ErrorStrResp(c, fmt.Sprintf("SSO user-info request failed: %s", resp.Status()), 400)
		return
	}
	if platform == "Feishu" && utils.Json.Get(resp.Body(), "code").ToInt() != 0 {
		log.Errorf("Feishu SSO user-info request failed: api_code=%d message=%q", utils.Json.Get(resp.Body(), "code").ToInt(), utils.Json.Get(resp.Body(), "msg").ToString())
		common.ErrorStrResp(c, "Feishu user-info request failed: "+utils.Json.Get(resp.Body(), "msg").ToString(), 400)
		return
	}
	userID := utils.Json.Get(resp.Body(), idField).ToString()
	username := utils.Json.Get(resp.Body(), usernameField).ToString()
	if platform == "Feishu" {
		// jsoniter expects nested object keys as separate path arguments rather
		// than a dot-separated string. The latter looked for a literal
		// "data.open_id" field and caused every successful Feishu callback to
		// fall through to the generic "error occurred" response.
		userID = utils.Json.Get(resp.Body(), "data", idField).ToString()
		username = utils.Json.Get(resp.Body(), "data", usernameField).ToString()
		if utils.SliceContains([]string{"", "0"}, userID) {
			log.Errorf("Feishu SSO user-info response is missing data.open_id: data_present=%t name_present=%t", utils.Json.Get(resp.Body(), "data").GetInterface() != nil, username != "")
			common.ErrorStrResp(c, "Feishu user-info response does not include open_id", 400)
			return
		}
	}
	if utils.SliceContains([]string{"", "0"}, userID) {
		common.ErrorResp(c, errors.New("error occurred"), 400)
		return
	}
	if argument == "get_sso_id" {
		if usecompatibility {
			c.Redirect(302, common.GetApiUrl(c.Request)+"/@manage?sso_id="+userID)
			return
		}
		html := fmt.Sprintf(`<!DOCTYPE html>
				<head></head>
				<body>
				<script>
				window.opener.postMessage({"sso_id": "%s"}, "*")
				window.close()
				</script>
				</body>`, userID)
		c.Data(200, "text/html; charset=utf-8", []byte(html))
		return
	}
	user, err := db.GetUserBySSOID(userID)
	autoRegistered := false
	if err != nil {
		user, err = autoRegister(username, userID, err)
		if err != nil {
			if platform == "Feishu" {
				log.Errorf("Feishu SSO could not resolve or auto-register the AList user: %v", err)
			}
			common.ErrorResp(c, err, 400)
			return
		}
		autoRegistered = true
	}
	token, err := common.GenerateToken(user)
	if err != nil {
		if platform == "Feishu" {
			log.Errorf("Feishu SSO could not generate an AList login token for user_id=%d: %v", user.ID, err)
		}
		common.ErrorResp(c, err, 400)
		return
	}
	if platform == "Feishu" {
		log.Infof("Feishu SSO login succeeded: alist_user_id=%d role_ids=%v auto_registered=%t", user.ID, user.Role, autoRegistered)
	}
	if usecompatibility {
		c.Redirect(302, common.GetApiUrl(c.Request)+"/@login?token="+token)
		return
	}
	html := fmt.Sprintf(`<!DOCTYPE html>
							<head></head>
							<body>
							<script>
							window.opener.postMessage({"token":"%s"}, "*")
							window.close()
							</script>
							</body>`, token)
	c.Data(200, "text/html; charset=utf-8", []byte(html))
}
