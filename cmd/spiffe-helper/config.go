package main

import (
	"io/ioutil"

	"github.com/hashicorp/hcl"
	"github.com/faisal-memon/spiffe-helper/pkg/spiffehelper"
)

// ParseConfig parses the given HCL file into a SidecarConfig struct
func ParseConfig(file string) (helperConfig *spiffehelper.Config, err error) {
	helperConfig = &spiffehelper.Config{
				AgentAddress:       `hcl:"agentAddress"`,
				Cmd:                `hcl:"cmd"`,
				CmdArgs:            `hcl:"cmdArgs"`,
				CertDir:            `hcl:"certDir"`,
				SvidFileName:       `hcl:"svidFileName"`,
				SvidKeyFileName:    `hcl:"svidKeyFileName"`,
				SvidBundleFileName: `hcl:"svidBundleFileName"`,
				RenewSignal:        `hcl:"renewSignal"`,
				Timeout:            `hcl:"timeout"`,
			}

	// Read HCL file
	dat, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	hclText := string(dat)

	// Parse HCL
	hclParseTree, err := hcl.Parse(hclText)
	if err != nil {
		return nil, err
	}

	if err := hcl.DecodeObject(&helperConfig, hclParseTree); err != nil {
		return nil, err
	}

	return helperConfig, nil
}
