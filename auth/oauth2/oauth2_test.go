/*
 * oauth2_test.go
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
	"testing"

	"github.com/billziss-gh/objfs/auth"
)

func TestOauth2(t *testing.T) {
	if false {
		cmap := auth.CredentialMap{}
		cmap["client_id"] = ""
		cmap["client_secret"] = ""
		cmap["redirect_uri"] = ""
		cmap["scope"] = "files.readwrite.all offline_access"
		err := auth.WriteCredentials("keyring:objfs/onedrive_client_secret", cmap)
		if nil != err {
			t.Fatal(err)
		}
	}

	cmap, err := auth.ReadCredentials("../../../../../../_test.onedrive_token")
	if nil != err {
		cmap, err = auth.ReadCredentials("keyring:objfs/onedrive_client_secret")
		if nil != err {
			t.Skip("required credentials missing: keyring:objfs/onedrive_client_secret")
		}
	}

	a, err := auth.Registry.NewObject("oauth2",
		"https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		"https://login.microsoftonline.com/common/oauth2/v2.0/token")
	if nil != err {
		t.Error()
	}

	sess, err := a.(auth.Auth).Session(cmap)
	if nil != err {
		t.Fatalf("%+v\n", err)
	}

	refr := sess.(auth.SessionRefresher)
	err = refr.Refresh(true)
	if nil != err {
		t.Errorf("%+v\n", err)
	}
}
