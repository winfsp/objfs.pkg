/*
 * onedrive_test.go
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

package onedrive

import (
	"fmt"
	"testing"

	"github.com/billziss-gh/objfs/auth"
	"github.com/billziss-gh/objfs/objio"
)

func TestOneDrive(t *testing.T) {
	cmap, err := auth.ReadCredentials("../../../../../../_test.onedrive_token")
	if nil != err {
		cmap, err = auth.ReadCredentials("keyring:objfs/onedrive_client_secret")
		if nil != err {
			t.Skip("required credentials missing: keyring:objfs/onedrive_client_secret")
		}
	}

	s, err := objio.Registry.NewObject(
		"onedrive", "https://graph.microsoft.com/v1.0/me/drive", cmap)
	if nil != err {
		t.Error(err)
	}

	storage := s.(objio.ObjectStorage)
	m, l, e := storage.List("/winfsp", "", 0)
	fmt.Println(e)
	fmt.Println(l)
	fmt.Println(m)
}
