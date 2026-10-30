package jarloader

// Telegram deep-link / Bot API recognition for the bytecode URL inventory.
//
// Cheats, mods and stealers routinely phone home through Telegram: a Bot API
// call (api.telegram.org/bot<token>/sendMessage) exfiltrates to whoever runs
// the bot, while t.me links point at chats, channels or invite gates. Static
// analysis cannot resolve a username to a human-vs-bot verdict (that needs
// getMe), so the parser labels what the LINK SHAPE proves and says exactly
// what is still unknown:
//
//	user_chat	t.me/<name> — human, channel or unsuffixed bot; resolve to tell
//	bot_chat	t.me/<name>bot, ?start= payloads — very likely a bot
//	invite		t.me/+hash, t.me/joinchat/hash — group/channel gate
//	channel		t.me/c/<id> — private channel/group link
//	bot_api		api.telegram.org/bot<token>/<method> — data goes to the bot
//	proxy		t.me/proxy, tg://proxy — MTProto proxy settings, not a peer
//	share		t.me/share/url — share-sheet template, not a peer
//	unknown		bare domain or unrecognized path
//
// The bot token itself is never stored: Target carries the API method only.

import (
	"net/url"
	"strings"
)

// TelegramLink is one parsed Telegram URL.
type TelegramLink struct {
	Kind   string `json:"kind"`
	Target string `json:"target,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// Telegram link kinds.
const (
	TGUserChat = "user_chat"
	TGBotChat  = "bot_chat"
	TGInvite   = "invite"
	TGChannel  = "channel"
	TGBotAPI   = "bot_api"
	TGProxy    = "proxy"
	TGShare    = "share"
	TGUnknown  = "unknown"
)

var telegramHosts = map[string]bool{
	"t.me": true, "www.t.me": true,
	"telegram.me": true, "www.telegram.me": true,
	"telegram.dog": true, "www.telegram.dog": true,
}

// ParseTelegramLink parses raw into a TelegramLink. ok=false means "not a
// Telegram peer URL" (unrelated host, or a Telegram web/docs domain that
// addresses no chat, user or bot).
func ParseTelegramLink(raw string) (tl TelegramLink, ok bool) {
	t := strings.TrimSpace(raw)
	lower := strings.ToLower(t)
	if strings.HasPrefix(lower, "tg://") {
		return parseTgScheme(t), true
	}
	var rest string
	for _, p := range []string{"https://", "http://"} {
		if strings.HasPrefix(lower, p) {
			rest = t[len(p):]
			break
		}
	}
	if rest == "" {
		return TelegramLink{}, false
	}
	u, err := url.Parse("https://" + rest)
	if err != nil {
		return TelegramLink{}, false
	}
	host := strings.ToLower(u.Hostname())
	if host == "api.telegram.org" {
		return parseBotAPI(u), true
	}
	if !telegramHosts[host] {
		return TelegramLink{}, false
	}
	return parseTmePath(u), true
}

func parseTmePath(u *url.URL) TelegramLink {
	p := strings.Trim(u.EscapedPath(), "/")
	q := u.Query()
	if p == "" {
		return TelegramLink{Kind: TGUnknown, Detail: "bare telegram domain, no target"}
	}
	segs := strings.Split(p, "/")
	switch {
	case strings.HasPrefix(segs[0], "+") && len(segs[0]) > 1:
		return TelegramLink{Kind: TGInvite, Target: segs[0][1:], Detail: "invite hash — group/channel gate, resolves server-side only"}
	case segs[0] == "joinchat" && len(segs) > 1:
		return TelegramLink{Kind: TGInvite, Target: segs[1], Detail: "legacy invite hash — group/channel gate"}
	case segs[0] == "proxy" || segs[0] == "socks":
		return TelegramLink{Kind: TGProxy, Detail: "MTProto proxy settings link, not a chat peer"}
	case segs[0] == "share" || segs[0] == "share/url":
		return TelegramLink{Kind: TGShare, Detail: "share-sheet template, not a chat peer"}
	case segs[0] == "c" && len(segs) > 1:
		return TelegramLink{Kind: TGChannel, Target: segs[1], Detail: "private channel/group link"}
	case segs[0] == "s" && len(segs) > 1:
		return classifyTgName(segs[1], "channel preview page")
	}
	if q.Get("start") != "" || q.Get("startgroup") != "" {
		return TelegramLink{Kind: TGBotChat, Target: segs[0], Detail: "deep-link payload (?start=) — only bots receive it"}
	}
	return classifyTgName(segs[0], "")
}

// classifyTgName splits bot vs user/chat by the enforced "bot" username
// suffix. Anything else stays user_chat with an explicit unknown-recipient
// note: channels and suffix-less bots look identical statically.
func classifyTgName(name, via string) TelegramLink {
	detail := "username link — human, channel or bot without suffix; resolve via getMe to tell"
	if via != "" {
		detail = via + " for " + detail
	}
	if strings.HasSuffix(strings.ToLower(name), "bot") {
		return TelegramLink{Kind: TGBotChat, Target: name, Detail: "bot username suffix — very likely a bot"}
	}
	return TelegramLink{Kind: TGUserChat, Target: name, Detail: detail}
}

// parseBotAPI handles api.telegram.org/bot<token>/<method>. The token is
// dropped on the floor: only the method (the WHAT) is reported, never the
// credential itself.
func parseBotAPI(u *url.URL) TelegramLink {
	p := strings.Trim(u.EscapedPath(), "/")
	segs := strings.Split(p, "/")
	if len(segs) == 0 || !strings.HasPrefix(strings.ToLower(segs[0]), "bot") {
		return TelegramLink{Kind: TGUnknown, Detail: "telegram API host without bot call"}
	}
	method := "unknown-method"
	if len(segs) > 1 && segs[1] != "" {
		method, _ = url.PathUnescape(segs[1])
	}
	return TelegramLink{
		Kind:   TGBotAPI,
		Target: method,
		Detail: "Bot API call — data goes to whoever runs the bot (and wherever the bot forwards it)",
	}
}

func parseTgScheme(raw string) TelegramLink {
	u, err := url.Parse(raw)
	if err != nil {
		return TelegramLink{Kind: TGUnknown, Detail: "unparsable tg:// link"}
	}
	opaque := strings.ToLower(u.Opaque)
	host := strings.ToLower(u.Host)
	action := opaque
	if action == "" {
		action = host
	}
	q := u.Query()
	switch {
	case strings.HasPrefix(action, "resolve"):
		if d := q.Get("domain"); d != "" {
			return classifyTgName(d, "tg://resolve link")
		}
		return TelegramLink{Kind: TGUnknown, Detail: "tg://resolve without domain"}
	case strings.HasPrefix(action, "join"):
		if inv := q.Get("invite"); inv != "" {
			return TelegramLink{Kind: TGInvite, Target: inv, Detail: "invite hash — group/channel gate"}
		}
		return TelegramLink{Kind: TGInvite, Detail: "join link without visible hash"}
	case strings.HasPrefix(action, "proxy") || strings.HasPrefix(action, "socks"):
		return TelegramLink{Kind: TGProxy, Detail: "MTProto proxy settings link, not a chat peer"}
	case strings.HasPrefix(action, "openmessage"):
		if id := q.Get("user_id"); id != "" {
			return TelegramLink{Kind: TGUserChat, Target: id, Detail: "direct message link by numeric user id"}
		}
		return TelegramLink{Kind: TGUserChat, Detail: "direct message link"}
	}
	return TelegramLink{Kind: TGUnknown, Detail: "unrecognized tg:// action"}
}
