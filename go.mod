module github.com/easyssl-io/easyssl-agent

go 1.26.10

require github.com/easyssl-io/easyssl-contract v0.2.0

// TODO: drop with the easyssl-contract 0.2.1 release; never merge to main with this replace.
replace github.com/easyssl-io/easyssl-contract => ../contract
