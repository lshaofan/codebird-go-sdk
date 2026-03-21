package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	codebird "github.com/lshaofan/codebird-go-sdk"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	ctx := context.Background()
	command := os.Args[1]

	switch command {
	case "list":
		if len(os.Args) < 3 {
			usage()
		}
		client := mustClient(os.Args[2])

		result, err := client.ListOrganizationMembers(ctx, os.Args[2], codebird.ListOrganizationMembersInput{
			Page:     1,
			PageSize: 20,
		})
		fatalIfErr(err)
		printJSON(result)
	case "add":
		if len(os.Args) < 4 {
			usage()
		}
		client := mustClient(os.Args[2])

		input := codebird.AddOrganizationMemberInput{
			Phone: os.Args[3],
		}
		if len(os.Args) >= 5 {
			input.Name = os.Args[4]
		}
		if len(os.Args) >= 6 {
			input.Email = os.Args[5]
		}

		result, err := client.AddOrganizationMember(ctx, os.Args[2], input)
		fatalIfErr(err)
		printJSON(result)
	case "remove":
		if len(os.Args) < 4 {
			usage()
		}
		client := mustClient(os.Args[2])

		fatalIfErr(client.RemoveOrganizationMember(ctx, os.Args[2], os.Args[3]))
		fmt.Println("ok")
	case "roles":
		if len(os.Args) < 4 {
			usage()
		}
		client := mustClient(os.Args[2])

		result, err := client.GetOrganizationMemberRoles(ctx, os.Args[2], os.Args[3])
		fatalIfErr(err)
		printJSON(result)
	case "update-roles":
		if len(os.Args) < 5 {
			usage()
		}
		client := mustClient(os.Args[2])

		input := codebird.UpdateOrganizationMemberRolesInput{
			RoleIDs: os.Args[4:],
		}
		fatalIfErr(client.UpdateOrganizationMemberRoles(ctx, os.Args[2], os.Args[3], input))
		fmt.Println("ok")
	default:
		usage()
	}
}

func mustClient(organizationID string) *codebird.M2MClient {
	client, err := codebird.NewM2MClient(codebird.M2MConfig{
		Endpoint:       mustEnv("CODEBIRD_ENDPOINT"),
		ClientID:       mustEnv("CODEBIRD_CLIENT_ID"),
		ClientSecret:   mustEnv("CODEBIRD_CLIENT_SECRET"),
		OrganizationID: organizationID,
		Resource:       optionalEnv("CODEBIRD_RESOURCE"),
	})
	if err != nil {
		log.Fatalf("failed to create m2m client: %v", err)
	}

	return client
}

func mustEnv(key string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		log.Fatalf("missing required env: %s", key)
	}

	return value
}

func optionalEnv(key string) string {
	return strings.TrimSpace(os.Getenv(key))
}

func fatalIfErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func printJSON(value any) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(data))
}

func usage() {
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  go run ./examples/m2m-organization-members list <organization-id>")
	fmt.Fprintln(os.Stderr, "  go run ./examples/m2m-organization-members add <organization-id> <phone> [name] [email]")
	fmt.Fprintln(os.Stderr, "  go run ./examples/m2m-organization-members remove <organization-id> <user-id>")
	fmt.Fprintln(os.Stderr, "  go run ./examples/m2m-organization-members roles <organization-id> <user-id>")
	fmt.Fprintln(os.Stderr, "  go run ./examples/m2m-organization-members update-roles <organization-id> <user-id> <role-id> [role-id...]")
	os.Exit(1)
}
