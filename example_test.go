// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi_test

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/johnnycube/kasapi"
)

// A client logs in on its first call and keeps the session.
func ExampleNew() {
	client, err := kasapi.New(kasapi.Config{
		Login:    os.Getenv("KAS_LOGIN"),
		Password: os.Getenv("KAS_PASSWORD"),
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	domains, err := client.Domains.List(context.Background())
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, d := range domains {
		fmt.Println(d.Name, d.Path)
	}
}

// The DNS-01 challenge of an ACME client is one TXT record.
func ExampleDNSService_Create() {
	client, _ := kasapi.New(kasapi.Config{Login: "w0123456", Password: os.Getenv("KAS_PASSWORD")})
	ctx := context.Background()

	id, err := client.DNS.Create(ctx, kasapi.DNSRecord{
		Zone: "example.com", Name: "_acme-challenge", Type: "TXT", Data: "token",
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	// Once the certificate is issued, the record goes again.
	fmt.Println(client.DNS.Delete(ctx, id))
}

// A missing object is ErrNotFound; any other KAS fault carries its code.
func ExampleSubdomainService_Get() {
	client, _ := kasapi.New(kasapi.Config{Login: "w0123456", Password: os.Getenv("KAS_PASSWORD")})

	sub, err := client.Subdomains.Get(context.Background(), "blog.example.com")
	var apiErr *kasapi.APIError
	switch {
	case errors.Is(err, kasapi.ErrNotFound):
		fmt.Println("no such subdomain")
	case errors.As(err, &apiErr):
		fmt.Println("KAS fault:", apiErr.Code)
	case err != nil:
		fmt.Println(err)
	default:
		fmt.Println(sub.Path, sub.PHPVersion, sub.TLS.LetsEncrypt())
	}
}

// Exec runs any KAS action, with the parameters the KAS docs list.
func ExampleClient_Exec() {
	client, _ := kasapi.New(kasapi.Config{Login: "w0123456", Password: os.Getenv("KAS_PASSWORD")})

	ret, err := client.Exec(context.Background(), "get_softwareinstall", map[string]any{})
	if err != nil {
		fmt.Println(err)
		return
	}
	// ret is map[string]any, []any or string, as KAS shaped it.
	fmt.Printf("%T\n", ret)
}
