package osin

import (
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// AuthorizeRequestType is the type for OAuth param `response_type`
type AuthorizeRequestType string

const (
	CODE  AuthorizeRequestType = "code"
	TOKEN AuthorizeRequestType = "token"
)

// Authorize request information
type AuthorizeRequest struct {
	Type        AuthorizeRequestType
	Client      Client
	Scope       string
	RedirectUri string
	State       string

	// Set if request is authorized
	Authorized bool

	// Token expiration in seconds. Change if different from default.
	// If type = TOKEN, this expiration will be for the ACCESS token.
	Expiration int32

	// Data to be passed to storage. Not used by the library.
	UserData interface{}

	// HttpRequest *http.Request for special use
	HttpRequest *http.Request
}

// Authorization data
type AuthorizeData struct {
	// Client information
	ClientId string `bson:"clientid"`

	// Authorization code
	Code string `bson:"code"`

	// Token expiration in seconds
	ExpiresIn int32 `bson:"expiresin"`

	// Requested scope
	Scope string `bson:"scope"`

	// Redirect Uri from request
	RedirectUri string `bson:"redirecturi"`

	// State data from request
	State string `bson:"state"`

	// Date created
	CreatedAt time.Time `bson:"createdat"`

	// Data to be passed to storage. Not used by the library.
	UserData interface{} `bson:"userdata"`
}

// IsExpired is true if authorization expired
func (d *AuthorizeData) IsExpired() bool {
	return d.IsExpiredAt(time.Now())
}

// IsExpired is true if authorization expires at time 't'
func (d *AuthorizeData) IsExpiredAt(t time.Time) bool {
	return d.ExpireAt().Before(t)
}

// ExpireAt returns the expiration date
func (d *AuthorizeData) ExpireAt() time.Time {
	return d.CreatedAt.Add(time.Duration(d.ExpiresIn) * time.Second)
}

// AuthorizeTokenGen is the token generator interface
type AuthorizeTokenGen interface {
	GenerateAuthorizeToken(data *AuthorizeData) (string, error)
}

// HandleAuthorizeRequest is the main http.HandlerFunc for handling
// authorization requests
func (s *Server) HandleAuthorizeRequest(w *Response, r *http.Request) *AuthorizeRequest {
	r.ParseForm()

	// create the authorization request
	unescapedUri, err := url.QueryUnescape(r.Form.Get("redirect_uri"))
	if err != nil {
		w.SetErrorState(E_INVALID_REQUEST, "", "")
		w.InternalError = err
		return nil
	}

	ret := &AuthorizeRequest{
		State:       r.Form.Get("state"),
		Scope:       r.Form.Get("scope"),
		RedirectUri: unescapedUri,
		Authorized:  false,
		HttpRequest: r,
	}
	if s.Config.EnableDebug {
		fmt.Println("HandleAuthorizeRequest Check GetClient")
	}
	// must have a valid client
	ret.Client, err = w.Storage.GetClient(r.Form.Get("client_id"))
	if err != nil {
		w.SetErrorState(E_SERVER_ERROR, "", ret.State)
		w.InternalError = err
		return nil
	}
	if s.Config.EnableDebug {
		fmt.Println("HandleAuthorizeRequest Check Client")
	}
	if ret.Client == nil {
		w.SetErrorState(E_UNAUTHORIZED_CLIENT, "", ret.State)
		return nil
	}
	if s.Config.EnableDebug {
		fmt.Println("HandleAuthorizeRequest Check GetRedirectUri")
	}
	if ret.Client.GetRedirectUri() == "" {
		w.SetErrorState(E_UNAUTHORIZED_CLIENT, "", ret.State)
		return nil
	}
	if s.Config.EnableDebug {
		fmt.Println("HandleAuthorizeRequest Check GetRedirectUri && FirstUri")
	}
	// check redirect uri, if there are multiple client redirect uri's
	// don't set the uri
	if ret.RedirectUri == "" && FirstUri(ret.Client.GetRedirectUri(), s.Config.RedirectUriSeparator) == ret.Client.GetRedirectUri() {
		ret.RedirectUri = FirstUri(ret.Client.GetRedirectUri(), s.Config.RedirectUriSeparator)
	}
	if s.Config.EnableDebug {
		fmt.Println("HandleAuthorizeRequest Check ValidateUriList", ret.RedirectUri,ret.Client.GetRedirectUri())
	}
	if err = ValidateUriList(ret.Client.GetRedirectUri(), ret.RedirectUri, s.Config.RedirectUriSeparator); err != nil {
		w.SetErrorState(E_INVALID_REQUEST, "", ret.State)
		w.InternalError = err
		return nil
	}
	if s.Config.EnableDebug {
		fmt.Println("HandleAuthorizeRequest SetRedirect", ret.RedirectUri)
	}
	w.SetRedirect(ret.RedirectUri)

	requestType := AuthorizeRequestType(r.Form.Get("response_type"))
	if s.Config.AllowedAuthorizeTypes.Exists(requestType) {
		switch requestType {
		case CODE:
			ret.Type = CODE
			ret.Expiration = s.Config.AuthorizationExpiration
		case TOKEN:
			ret.Type = TOKEN
			ret.Expiration = s.Config.AccessExpiration
		}
		return ret
	}

	w.SetErrorState(E_UNSUPPORTED_RESPONSE_TYPE, "", ret.State)
	return nil
}

func (s *Server) FinishAuthorizeRequest(w *Response, r *http.Request, ar *AuthorizeRequest) {
	// don't process if is already an error
	if w.IsError {
		return
	}

	// force redirect response
	w.SetRedirect(ar.RedirectUri)

	if ar.Authorized {
		if ar.Type == TOKEN {
			//HOPJOY
			if false {
				w.SetRedirectFragment(true)
			}

			// generate token directly
			ret := &AccessRequest{
				Type:            IMPLICIT,
				Code:            "",
				Client:          ar.Client,
				RedirectUri:     ar.RedirectUri,
				Scope:           ar.Scope,
				GenerateRefresh: false, // per the RFC, should NOT generate a refresh token in this case
				Authorized:      true,
				Expiration:      ar.Expiration,
				UserData:        ar.UserData,
			}

			s.FinishAccessRequest(w, r, ret)
			if ar.State != "" && w.InternalError == nil {
				w.Output["state"] = ar.State
			}
		} else {
			// generate authorization token
			ret := &AuthorizeData{
				ClientId:    ar.Client.GetId(),
				CreatedAt:   s.Now(),
				ExpiresIn:   ar.Expiration,
				RedirectUri: ar.RedirectUri,
				State:       ar.State,
				Scope:       ar.Scope,
				UserData:    ar.UserData,
			}

			// generate token code
			code, err := s.AuthorizeTokenGen.GenerateAuthorizeToken(ret)
			if err != nil {
				w.SetErrorState(E_SERVER_ERROR, "", ar.State)
				w.InternalError = err
				return
			}
			ret.Code = code

			// save authorization token
			if err = w.Storage.SaveAuthorize(ret); err != nil {
				w.SetErrorState(E_SERVER_ERROR, "", ar.State)
				w.InternalError = err
				return
			}

			// redirect with code
			w.Output["code"] = ret.Code
			w.Output["state"] = ret.State
		}
	} else {
		// redirect with error
		w.SetErrorState(E_ACCESS_DENIED, "", ar.State)
	}
}
