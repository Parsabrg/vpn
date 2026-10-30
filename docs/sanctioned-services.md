# Sanctioned services only

Some services refuse connections from Iranian addresses. That is not the
filter: Iran lets the request out, and the service itself answers with a 403
or "not available in your region". They need an address outside Iran, not a
tunnel through the filter.

"Sanctioned services only" sends exactly those services -- and DNS -- through
a server abroad, and everything else directly. Domestic sites stay fast, and
the server carries a fraction of the traffic. It does **not** get past
censorship: a filtered site stays filtered in this mode.

The Nebula app has it as a switch under **Settings → Protection** (VLESS
profiles; Hysteria2 and WireGuard tunnel everything regardless). This page is
the same routing for any other Xray client (v2rayN, v2rayNG).

## The list

The source of truth is
[`apps/mobile/lib/core/routing/sanctioned_domains.dart`](../apps/mobile/lib/core/routing/sanctioned_domains.dart).
Every block below is generated from it, and a test fails if they disagree.

`domain:` matches the name and all its subdomains. 49 entries.

## How the rules work

Order matters, and the last rule is the one people leave out:

1. The listed domains go to the server.
2. Port 53 goes to the server, so DNS keeps working and stays private however
   the local network treats it.
3. **Everything else goes direct.** Without this rule an Xray client sends
   anything unmatched to its first outbound -- the server -- which is the
   opposite of the mode.

Matching a domain needs the hostname, so **sniffing must be on** (HTTP, TLS
and QUIC). With sniffing off every connection falls through to rule 3 and the
tunnel carries nothing while looking connected.

## v2rayNG (Android)

**Settings → Routing settings → ⋮ → Import custom rules** (from clipboard),
then set **Domain strategy** to `AsIs`. In **Settings**, turn on **Enable
sniffing** with `http`, `tls` and `quic`.

```json
[
  {
    "remarks": "Sanctioned services via the server",
    "outboundTag": "proxy",
    "domain": [
      "domain:nvidia.com",
      "domain:geforce.com",
      "domain:geforcenow.com",
      "domain:nvidiagrid.net",
      "domain:docker.com",
      "domain:docker.io",
      "domain:developer.android.com",
      "domain:dl.google.com",
      "domain:maven.google.com",
      "domain:gradle.org",
      "domain:gradle.com",
      "domain:flutter.dev",
      "domain:dart.dev",
      "domain:pub.dev",
      "domain:storage.googleapis.com",
      "domain:developers.google.com",
      "domain:firebase.google.com",
      "domain:firebaseio.com",
      "domain:cloud.google.com",
      "domain:aistudio.google.com",
      "domain:gemini.google.com",
      "domain:generativelanguage.googleapis.com",
      "domain:colab.research.google.com",
      "domain:openai.com",
      "domain:chatgpt.com",
      "domain:oaistatic.com",
      "domain:oaiusercontent.com",
      "domain:anthropic.com",
      "domain:claude.ai",
      "domain:claude.com",
      "domain:perplexity.ai",
      "domain:githubcopilot.com",
      "domain:developer.apple.com",
      "domain:jetbrains.com",
      "domain:oracle.com",
      "domain:atlassian.com",
      "domain:atlassian.net",
      "domain:bitbucket.org",
      "domain:hashicorp.com",
      "domain:terraform.io",
      "domain:figma.com",
      "domain:slack.com",
      "domain:epicgames.com",
      "domain:unrealengine.com",
      "domain:coursera.org",
      "domain:udemy.com",
      "domain:spotify.com",
      "domain:spotifycdn.com",
      "domain:scdn.co"
    ],
    "enabled": true
  },
  {
    "remarks": "DNS via the server",
    "outboundTag": "proxy",
    "port": "53",
    "enabled": true
  },
  {
    "remarks": "Everything else direct",
    "outboundTag": "direct",
    "port": "0-65535",
    "enabled": true
  }
]
```

## v2rayN (Windows) -- for apps like the NVIDIA app

The NVIDIA app and most games ignore the Windows system proxy, so use
**TUN mode** (Settings → TUN mode settings → enable), not "Set system proxy".

**Settings → Routing settings → Add**, name it *Sanctioned services only*,
domain strategy `AsIs`, and add three rules in this order:

| # | Outbound | Match |
| --- | --- | --- |
| 1 | `proxy` | Domain: paste the list below, one per line |
| 2 | `proxy` | Port: `53` |
| 3 | `direct` | Port: `0-65535` |

Select it as the active routing, and keep sniffing enabled in the core
settings.

<details>
<summary>The domain list, one per line</summary>

```
domain:nvidia.com
domain:geforce.com
domain:geforcenow.com
domain:nvidiagrid.net
domain:docker.com
domain:docker.io
domain:developer.android.com
domain:dl.google.com
domain:maven.google.com
domain:gradle.org
domain:gradle.com
domain:flutter.dev
domain:dart.dev
domain:pub.dev
domain:storage.googleapis.com
domain:developers.google.com
domain:firebase.google.com
domain:firebaseio.com
domain:cloud.google.com
domain:aistudio.google.com
domain:gemini.google.com
domain:generativelanguage.googleapis.com
domain:colab.research.google.com
domain:openai.com
domain:chatgpt.com
domain:oaistatic.com
domain:oaiusercontent.com
domain:anthropic.com
domain:claude.ai
domain:claude.com
domain:perplexity.ai
domain:githubcopilot.com
domain:developer.apple.com
domain:jetbrains.com
domain:oracle.com
domain:atlassian.com
domain:atlassian.net
domain:bitbucket.org
domain:hashicorp.com
domain:terraform.io
domain:figma.com
domain:slack.com
domain:epicgames.com
domain:unrealengine.com
domain:coursera.org
domain:udemy.com
domain:spotify.com
domain:spotifycdn.com
domain:scdn.co
```

</details>

## Raw Xray client config

For any other Xray-core client, this `routing` block goes beside an outbound
tagged `proxy` (the server) and one tagged `direct`
(`{"tag": "direct", "protocol": "freedom"}`), with sniffing on the inbound:

```json
{
  "domainStrategy": "AsIs",
  "rules": [
    {
      "type": "field",
      "outboundTag": "proxy",
      "domain": [
        "domain:nvidia.com",
        "domain:geforce.com",
        "domain:geforcenow.com",
        "domain:nvidiagrid.net",
        "domain:docker.com",
        "domain:docker.io",
        "domain:developer.android.com",
        "domain:dl.google.com",
        "domain:maven.google.com",
        "domain:gradle.org",
        "domain:gradle.com",
        "domain:flutter.dev",
        "domain:dart.dev",
        "domain:pub.dev",
        "domain:storage.googleapis.com",
        "domain:developers.google.com",
        "domain:firebase.google.com",
        "domain:firebaseio.com",
        "domain:cloud.google.com",
        "domain:aistudio.google.com",
        "domain:gemini.google.com",
        "domain:generativelanguage.googleapis.com",
        "domain:colab.research.google.com",
        "domain:openai.com",
        "domain:chatgpt.com",
        "domain:oaistatic.com",
        "domain:oaiusercontent.com",
        "domain:anthropic.com",
        "domain:claude.ai",
        "domain:claude.com",
        "domain:perplexity.ai",
        "domain:githubcopilot.com",
        "domain:developer.apple.com",
        "domain:jetbrains.com",
        "domain:oracle.com",
        "domain:atlassian.com",
        "domain:atlassian.net",
        "domain:bitbucket.org",
        "domain:hashicorp.com",
        "domain:terraform.io",
        "domain:figma.com",
        "domain:slack.com",
        "domain:epicgames.com",
        "domain:unrealengine.com",
        "domain:coursera.org",
        "domain:udemy.com",
        "domain:spotify.com",
        "domain:spotifycdn.com",
        "domain:scdn.co"
      ]
    },
    {
      "type": "field",
      "outboundTag": "proxy",
      "port": "53"
    },
    {
      "type": "field",
      "outboundTag": "direct",
      "network": "tcp,udp"
    }
  ]
}
```

## The server needs no change

A server only ever sees traffic its client chose to send it, so the split is
entirely the client's. Any VLESS server serves this mode
exactly as it is.
