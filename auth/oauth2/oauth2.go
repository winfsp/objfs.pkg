/*
 * oauth2.go
 *
 * Copyright 2018 Bill Zissimopoulos
 */
/*
 * This file is part of Objfs.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * Affero General Public License version 3 as published by the Free
 * Software Foundation.
 *
 * Licensees holding a valid commercial license may use this file in
 * accordance with the commercial license agreement provided with the
 * software.
 */

package oauth2

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/billziss-gh/golib/errors"
	"github.com/billziss-gh/objfs/assets"
	"github.com/billziss-gh/objfs/auth"
	"github.com/billziss-gh/objfs/errno"
	"github.com/billziss-gh/objfs/httputil"
)

type oauth2Session struct {
	owner *oauth2
	creds auth.CredentialMap
	mux   sync.Mutex
}

type oauth2 struct {
	authUri    *url.URL
	tokenUri   *url.URL
	httpClient *http.Client
}

func credCopy(ocreds auth.CredentialMap, icreds auth.CredentialMap, name string) {
	v := icreds.Get(name)
	if "" == v {
		return
	}
	ocreds[name] = v
}

func credSetDeadline(creds auth.CredentialMap, now time.Time) {
	v := creds.Get("expires_in")
	i, err := strconv.ParseInt(v, 10, 64)
	if nil != err {
		return
	}
	d := now.Add(time.Duration(i) * time.Second)
	now = time.Now()
	if d.Before(now) {
		d = now.Add(time.Duration(60) * time.Second)
	}
	creds["deadline"] = d.Format(time.RFC3339)
}

func credGetRedirUri(creds auth.CredentialMap) *url.URL {
	redirUri, err := url.Parse(creds.Get("redirect_uri"))
	if nil != err {
		redirUri = &url.URL{
			Scheme: "http",
			Host:   "localhost",
		}
	}
	return redirUri
}

func (self *oauth2Session) Credentials() auth.CredentialMap {
	self.mux.Lock()
	defer self.mux.Unlock()
	return self.creds
}

func (self *oauth2Session) Refresh(force bool) error {
	icreds := self.Credentials()
	now := time.Now()
	if !force {
		v := icreds.Get("deadline")
		d, err := time.Parse(time.RFC3339, v)
		if nil == err && now.Before(d) {
			return nil
		}
	}

	ocreds, err := self.owner.getAccessToken(icreds, "refresh_token")
	if nil != err {
		return errors.New("", err, errno.EACCES)
	}

	creds := auth.CredentialMap{}
	credCopy(creds, icreds, "client_id")
	credCopy(creds, icreds, "client_secret")
	credCopy(creds, ocreds, "access_token")
	credCopy(creds, ocreds, "token_type")
	credCopy(creds, ocreds, "expires_in")
	credCopy(creds, ocreds, "refresh_token")
	credSetDeadline(creds, now)

	self.mux.Lock()
	defer self.mux.Unlock()
	self.creds = creds

	return nil
}

func (self *oauth2) Session(icreds auth.CredentialMap) (auth.Session, error) {
	var ocreds, creds auth.CredentialMap
	var err error
	if "" == icreds.Get("access_token") {
		if "" == icreds.Get("code") {
			const PORT = "PORTa652775f7e51adb7c70f064a0dd18b2ePORT"
			redirUri := credGetRedirUri(icreds)
			port := redirUri.Port()
			if "" == port {
				port = "0"
			}
			redirUri.Host = redirUri.Hostname() + ":" + PORT

			authUri := *self.authUri
			values := authUri.Query()
			values.Add("response_type", "code")
			values.Add("client_id", icreds.Get("client_id"))
			values.Add("redirect_uri", redirUri.String())
			if scope := icreds.Get("scope"); "" != scope {
				values.Add("scope", scope)
			}
			if state := icreds.Get("state"); "" != state {
				values.Add("state", state)
			}
			authUri.RawQuery = strings.Replace(values.Encode(), PORT, "[]", -1)

			helper := assets.GetPath("sys", "oauth2-helper")
			out, err := exec.Command(helper, "-p"+port, authUri.String()).Output()
			if nil != err {
				return nil, errors.New(": execute oauth2-helper", err, errno.EACCES)
			}

			res := string(out)
			if !strings.HasPrefix(res, "+") {
				return nil, errors.New(": oauth2-helper bad result", nil, errno.EACCES)
			}
			res = strings.TrimSpace(res[1:])

			resUri, err := url.Parse(res)
			if nil != err {
				return nil, errors.New(": oauth2-helper bad result", err, errno.EACCES)
			}

			values = resUri.Query()
			if resErr := values.Get("error"); "" != resErr {
				if resErrDesc := values.Get("error_description"); "" != resErrDesc {
					resErr += ": " + resErrDesc
				}
				return nil, errors.New(": oauth2 error: "+resErr, nil, errno.EACCES)
			}

			ocreds = auth.CredentialMap{}
			credCopy(ocreds, icreds, "client_id")
			credCopy(ocreds, icreds, "client_secret")
			credCopy(ocreds, icreds, "redirect_uri")
			ocreds["code"] = values.Get("code")
			icreds = ocreds
		}

		now := time.Now()
		ocreds, err = self.getAccessToken(icreds, "authorization_code")
		if nil != err {
			return nil, errors.New("", err, errno.EACCES)
		}

		creds = auth.CredentialMap{}
		credCopy(creds, icreds, "client_id")
		credCopy(creds, icreds, "client_secret")
		credCopy(creds, ocreds, "access_token")
		credCopy(creds, ocreds, "token_type")
		credCopy(creds, ocreds, "expires_in")
		credCopy(creds, ocreds, "refresh_token")
		credSetDeadline(creds, now)
	} else {
		creds = auth.CredentialMap{}
		credCopy(creds, icreds, "client_id")
		credCopy(creds, icreds, "client_secret")
		credCopy(creds, icreds, "access_token")
		credCopy(creds, icreds, "token_type")
		credCopy(creds, icreds, "expires_in")
		credCopy(creds, icreds, "refresh_token")
		credCopy(creds, icreds, "deadline")
	}

	session := &oauth2Session{
		owner: self,
		creds: creds,
		mux:   sync.Mutex{},
	}

	return session, nil
}

func (self *oauth2) getAccessToken(
	icreds auth.CredentialMap, grant_type string) (auth.CredentialMap, error) {
	tokenUri := *self.tokenUri
	values := tokenUri.Query()
	values.Add("grant_type", grant_type)
	if "authorization_code" == grant_type {
		redirUri := credGetRedirUri(icreds)
		values.Add("code", icreds.Get("code"))
		values.Add("redirect_uri", redirUri.String())
	} else if "refresh_token" == grant_type {
		values.Add("refresh_token", icreds.Get("refresh_token"))
	}
	values.Add("client_id", icreds.Get("client_id"))
	if client_secret := icreds.Get("client_secret"); "" != client_secret {
		values.Add("client_secret", client_secret)
	}
	tokenUri.RawQuery = ""

	body := strings.NewReader(values.Encode())
	rsp, err := httputil.Retry(body, func() (*http.Response, error) {
		return self.httpClient.Post(tokenUri.String(), "application/x-www-form-urlencoded", body)
	})
	if nil != err {
		return nil, err
	}
	defer rsp.Body.Close()

	rspOk := false
	if 200 == rsp.StatusCode || 400 == rsp.StatusCode {
		contentType := rsp.Header.Get("Content-type")
		if strings.HasPrefix(contentType, "application/json") ||
			strings.HasPrefix(contentType, "text/javascript") {
			rspOk = true
		}
	}
	if !rspOk {
		return nil, errors.New(": bad HTTP status or content-type", nil, errno.EACCES)
	}

	ocreds := auth.CredentialMap{}
	err = json.NewDecoder(rsp.Body).Decode(&ocreds)
	if nil != err {
		return nil, err
	}

	if errcode := ocreds.Get("error"); "" != errcode {
		if errmesg := ocreds.Get("error_description"); "" != errmesg {
			errcode += ": " + errmesg
		}
		return nil, errors.New(": oauth2 error: "+errcode, nil, errno.EACCES)
	}

	return ocreds, nil
}

// New creates a new oauth2 authorizer suitable for native apps.
func New(args ...interface{}) (interface{}, error) {
	var (
		authUri, tokenUri *url.URL
		httpClient        = httputil.DefaultClient
	)

	for _, arg := range args {
		switch a := arg.(type) {
		case string:
			uri, err := url.Parse(a)
			if nil != err {
				return nil, errors.New(": invalid uri "+a, err, errno.EINVAL)
			}
			if nil == authUri {
				authUri = uri
			} else if nil == tokenUri {
				tokenUri = uri
			}
		case *http.Client:
			httpClient = a
		}
	}

	if nil == authUri {
		return nil, errors.New(": missing authUri", nil, errno.EINVAL)
	}
	if nil == tokenUri {
		return nil, errors.New(": missing tokenUri", nil, errno.EINVAL)
	}

	self := &oauth2{
		authUri:    authUri,
		tokenUri:   tokenUri,
		httpClient: httpClient,
	}

	return self, nil
}

var _ auth.Session = (*oauth2Session)(nil)
var _ auth.SessionRefresher = (*oauth2Session)(nil)
var _ auth.Auth = (*oauth2)(nil)

// Load is used to ensure that this package is linked.
func Load() {
}

func init() {
	auth.Registry.RegisterFactory("oauth2", New)
}
