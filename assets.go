package main

import _ "embed"

//go:embed default_settings.json
var defaultSettingsJSON []byte

//go:embed certs/node.crt
var embeddedNodeCert []byte
