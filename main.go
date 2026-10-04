package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

const roleCombined = "combined"

func main() {
	args := os.Args[1:]

	role := roleCombined
	rest := args
	if len(args) > 0 && args[0] != "" && !strings.HasPrefix(args[0], "-") {
		role = args[0]
		rest = args[1:]
	}

	configPath := "settings.json"
	roleFlag := ""
	positional := []string{}
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case "--config":
			if i+1 < len(rest) {
				configPath = rest[i+1]
				i++
			}
		case "--role":
			if i+1 < len(rest) {
				roleFlag = rest[i+1]
				i++
			}
		default:
			positional = append(positional, rest[i])
		}
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		if writeErr := os.WriteFile(configPath, defaultSettingsJSON, 0o644); writeErr != nil {
			log.Fatalf("cannot create default config %s: %v", configPath, writeErr)
		}
		log.Printf("default config written to %s", configPath)
	}

	settings, err := LoadSettings(configPath)
	if err != nil {
		log.Fatalf("settings: %v", err)
	}
	settings.Role = role

	logger, closeLog := setupLogging(settings.LogFile)
	defer closeLog()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch role {
	case "node":
		if len(positional) > 0 && positional[0] == "allow" {
			if len(positional) < 2 {
				logger.Fatalf("usage: surface node allow <public_key> [--role agent|client] [--config path]")
			}
			allowRole := roleFlag
			if allowRole == "" {
				allowRole = "agent"
			}
			if err := allowKey(settings, positional[1], allowRole); err != nil {
				logger.Fatalf("allow: %v", err)
			}
			logger.Printf("key authorized: %s (role=%s)", positional[1], allowRole)
			return
		}
		err = runNode(ctx, settings, logger)
	case "agent":
		if len(positional) > 0 && positional[0] == "id" {
			err = printIdentity(settings)
			break
		}
		err = runAgent(ctx, settings, logger)
	case "client":
		if len(positional) > 0 && positional[0] == "id" {
			err = printIdentity(settings)
			break
		}
		err = runClient(ctx, settings, logger)
	case roleCombined:
		err = runCombined(ctx, settings, logger)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil && err != context.Canceled {
		logger.Fatalf("%v", err)
	}
}

func printIdentity(s *Settings) error {
	switch s.Role {
	case "client":
		priv, err := LoadOrCreateKey(s.ClientKeyFile)
		if err != nil {
			return err
		}
		fmt.Printf("public key: %s\n", PublicKeyString(priv.Public().(ed25519.PublicKey)))
		return nil
	case "agent":
		identities, err := groupByIdentity(s)
		if err != nil {
			return err
		}
		if len(identities) == 0 {
			identities = []*agentIdentity{{dir: s.IdentityDir}}
		}
		for _, identity := range identities {
			priv, err := LoadOrCreateKey(filepath.Join(identity.dir, "secret.key"))
			if err != nil {
				return err
			}
			pub := priv.Public().(ed25519.PublicKey)
			fmt.Printf("identity_dir: %s\npublic key: %s\nsurface name: %s\n",
				identity.dir, PublicKeyString(pub), DeriveName(pub))
		}
		return nil
	default:
		return errors.New("id is only available for the client and agent roles")
	}
}

func setupLogging(path string) (*log.Logger, func()) {
	writers := []io.Writer{os.Stderr}
	if path == "" {
		return log.New(io.MultiWriter(writers...), "", log.LstdFlags), func() {}
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return log.New(io.MultiWriter(writers...), "", log.LstdFlags), func() {}
	}
	writers = append(writers, file)
	return log.New(io.MultiWriter(writers...), "", log.LstdFlags), func() { file.Close() }
}

func allowKey(settings *Settings, keyString, role string) error {
	if role != "agent" && role != "client" {
		return fmt.Errorf("invalid role %q (use agent or client)", role)
	}
	pub, err := ParsePublicKey(keyString)
	if err != nil {
		return err
	}
	db, err := OpenDB(settings.DBName)
	if err != nil {
		return err
	}
	if sqlDB, err := db.DB(); err == nil {
		defer sqlDB.Close()
	}
	return NewRegistry(db).UpsertNodeKey("", PublicKeyString(pub), role, true)
}

func usage() {
	log.Println("surface: private .surface network proxy")
	log.Println("usage:")
	log.Println("  surface          [--config settings.json]   run client + agent (default, Tor-like)")
	log.Println("  surface node     [--config settings.json]")
	log.Println("  surface agent    [--config settings.json]")
	log.Println("  surface client   [--config settings.json]")
	log.Println("  surface node allow <public_key> [--role agent|client] [--config settings.json]")
	log.Println("  surface agent id [--config settings.json]")
	log.Println("  surface client id [--config settings.json]")
}
