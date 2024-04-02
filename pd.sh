#!/bin/bash
GOBIN=/usr/local/bin/ go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
GOBIN=/usr/local/bin/ go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
GOBIN=/usr/local/bin/ go install github.com/projectdiscovery/httpx/cmd/httpx@latest
GOBIN=/usr/local/bin/ go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
GOBIN=/usr/local/bin/ go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest
GOBIN=/usr/local/bin/ go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest
GOBIN=/usr/local/bin/ go install github.com/projectdiscovery/katana/cmd/katana@latest
