module github.com/easyssl-io/easyssl-agent

go 1.26.10

require github.com/easyssl-io/easyssl-contract v0.0.1

// Umbrella-dev resolution for the unpublished contract module. The Go workspace
// (go.work) handles dev builds; this replace lets the public module also build
// standalone with GOWORK=off from within the umbrella checkout. It is dropped in
// favor of a version pin once easyssl-contract is published.
replace github.com/easyssl-io/easyssl-contract => ../contract
