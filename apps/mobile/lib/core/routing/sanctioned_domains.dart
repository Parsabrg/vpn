/// Services that refuse connections from Iranian addresses.
///
/// Not censorship: these are blocked by the service itself, on the far side,
/// because of sanctions. Iran's filter lets the request out and the provider
/// answers it with a 403 or a "not available in your region" page. So they
/// need an address outside Iran, not a tunnel through the filter -- which is
/// what "sanctioned services only" gives them, while everything else keeps
/// its direct, domestic route.
///
/// Xray's `domain:` matches the name and every subdomain. Kept to services
/// that are known to geo-block Iran and that people actually need; a name
/// that is not sanctioned only costs a detour through the server, but a list
/// padded with guesses makes the mode slower for no one's benefit.
///
/// The same list is published for use outside the app -- see
/// docs/sanctioned-services.md -- so any other Xray client (v2rayN,
/// v2rayNG) can route identically.
library;

const List<String> sanctionedDomains = <String>[
  // Graphics drivers and the NVIDIA app.
  'domain:nvidia.com',
  'domain:geforce.com',
  'domain:geforcenow.com',
  'domain:nvidiagrid.net',

  // Container images.
  'domain:docker.com',
  'domain:docker.io',

  // Android and Flutter builds: the SDK, Maven, Gradle and pub.
  'domain:developer.android.com',
  'domain:dl.google.com',
  'domain:maven.google.com',
  'domain:gradle.org',
  'domain:gradle.com',
  'domain:flutter.dev',
  'domain:dart.dev',
  'domain:pub.dev',
  'domain:storage.googleapis.com',

  // Google developer and AI services.
  'domain:developers.google.com',
  'domain:firebase.google.com',
  'domain:firebaseio.com',
  'domain:cloud.google.com',
  'domain:aistudio.google.com',
  'domain:gemini.google.com',
  'domain:generativelanguage.googleapis.com',
  'domain:colab.research.google.com',

  // AI assistants.
  'domain:openai.com',
  'domain:chatgpt.com',
  'domain:oaistatic.com',
  'domain:oaiusercontent.com',
  'domain:anthropic.com',
  'domain:claude.ai',
  'domain:claude.com',
  'domain:perplexity.ai',
  'domain:githubcopilot.com',

  // Developer tools and accounts.
  'domain:developer.apple.com',
  'domain:jetbrains.com',
  'domain:oracle.com',
  'domain:atlassian.com',
  'domain:atlassian.net',
  'domain:bitbucket.org',
  'domain:hashicorp.com',
  'domain:terraform.io',
  'domain:figma.com',
  'domain:slack.com',

  // Games and learning.
  'domain:epicgames.com',
  'domain:unrealengine.com',
  'domain:coursera.org',
  'domain:udemy.com',

  // Music.
  'domain:spotify.com',
  'domain:spotifycdn.com',
  'domain:scdn.co',
];
