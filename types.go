package main

type PackageLicense struct {
	PackageName    string
	PackageLicense string
}

type PluginConfig struct {
	Name               string    `json:"name"`
	DisallowedLicenses []string  `json:"disAllowedLicenses"`
	DisallowedPackages []Package `json:"disallowedPackages"`
}

type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type PluginInputConfig struct {
	Config PluginConfig `json:"config"`
}
