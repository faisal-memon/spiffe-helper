package main

import (
	"context"
	"flag"
	"log"

	"github.com/faisal-memon/spiffe-helper/pkg/spiffehelper"
)

func main() {
	// 0. Load configuration
	// 1. Create Sidecar
	// 2. Run Sidecar's Daemon

	configFile := flag.String("config", "helper.conf", "<configFile> Configuration file path")
	flag.Parse()

	config, err := ParseConfig(*configFile)
	if err != nil {
		log.Fatalf("error parsing configuration file: %v\n%v", *configFile, err)
	}

	log.Printf("Connecting to agent at %q\n", config.AgentAddress)
	if config.Cmd == "" {
		log.Println("Warning: no cmd defined to execute.")
	}

	log.Printf("Using configuration file: %q\n", *configFile)

	helper, err := spiffehelper.NewHelper(config)
	if err != nil {
		panic(err)
	}

	ctx := context.Background()
	helper.RunDaemon(ctx)
}
