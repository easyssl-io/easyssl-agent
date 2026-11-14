package acmeclients

import (
	"github.com/easyssl-io/easyssl-agent/internal/msg"
	"github.com/easyssl-io/easyssl-contract/l10n"
	"github.com/easyssl-io/easyssl-contract/plugincontract"
)

// Reason is the finding as one of the Agent's messages: why easySSL does not
// deploy there and what to do instead. It never names the Target's own path,
// which a reader sees beside it, so every Target in the same situation reads
// the same and a reader can group them; and it is worded to read for one path
// or several, since a group lists every path under one copy of it.
func (f Finding) Reason() error {
	switch f.Kind {
	case Certbot:
		return msg.Err.T("acme.warning.certbot",
			"Certbot manages {dir}, so easySSL does not deploy there. Run `sudo easyssl-agent migrate` to move certificates out of it.",
			"dir", plugincontract.Code(f.Dir))
	case HookCopy:
		if f.LineageInUse {
			return msg.Err.T("acme.warning.hook_copy_in_use",
				"A certbot deploy hook keeps copying certbot's current certificate {lineage} here, so easySSL does not deploy there. Run `sudo easyssl-agent migrate` first to move what still uses certbot's own files.",
				"lineage", plugincontract.Code(f.Lineage.Name))
		}
		return msg.Err.T("acme.warning.hook_copy",
			"A certbot deploy hook keeps copying certbot's current certificate {lineage} here, so easySSL does not deploy there. Once nothing else uses that certificate, run {command}; otherwise remove the hook that copies it.",
			"lineage", plugincontract.Code(f.Lineage.Name), "command", plugincontract.Code(f.Lineage.DeleteCommand()))
	default:
		return msg.Err.T("acme.warning.other_client",
			"{dir} is managed by {client}, so easySSL does not deploy there. Point the web server at a location outside it to deploy with easySSL.",
			"dir", plugincontract.Code(f.Dir), "client", f.Client)
	}
}

// Warning is Reason in every language, as a discovered Target carries it to
// the Server.
func (f Finding) Warning() l10n.Text { return msg.TextOf(f.Reason()) }
