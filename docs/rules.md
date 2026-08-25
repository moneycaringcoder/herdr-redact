> **Generated file — detection rule catalogue.** This file is generated from the compiled rule set by `tests/rule_catalogue.rs`.
> Regenerate it with `REDACT_WRITE_RULE_CATALOGUE=1 cargo test --test rule_catalogue`. Editing it by hand is pointless because that test compares the committed file byte-for-byte with a fresh rendering.

# Detection rule catalogue

Strong confidence means the format is structurally identifiable; weak confidence means the match is a hint. Every rule is listed with what it rejects as well as what it matches.

## Summary

| Rule | Label | Confidence | Pack | Version |
| --- | --- | --- | --- | ---: |
| `aws_access_key_id` | AWS access key ID | strong | `default` | 1 |
| `aws_principal_id` | AWS principal ID (identifier, not a credential) | weak | `default` | 1 |
| `aws_secret_access_key` | AWS secret access key | strong | `default` | 1 |
| `github_token` | GitHub token | strong | `default` | 1 |
| `github_pat` | GitHub fine-grained token | strong | `default` | 1 |
| `anthropic_api_key` | Anthropic API key | strong | `default` | 1 |
| `openai_api_key` | OpenAI API key | strong | `default` | 1 |
| `stripe_secret_key` | Stripe live secret key | strong | `default` | 1 |
| `slack_token` | Slack token | strong | `default` | 1 |
| `google_api_key` | Google API key | strong | `default` | 1 |
| `google_oauth_client_secret` | Google OAuth client secret | strong | `default` | 1 |
| `jwt` | JSON Web Token | strong | `default` | 1 |
| `private_key_block` | Private key block | strong | `default` | 1 |
| `slack_webhook_url` | Slack webhook URL | strong | `default` | 1 |
| `npm_token` | npm access token | strong | `default` | 1 |
| `pypi_token` | PyPI API token | strong | `default` | 1 |
| `sendgrid_api_key` | SendGrid API key | strong | `default` | 1 |
| `gitlab_pat` | GitLab personal access token | strong | `default` | 1 |
| `grafana_service_account_token` | Grafana service account token | strong | `default` | 1 |
| `huggingface_token` | Hugging Face token | strong | `default` | 1 |
| `age_secret_key` | age secret key | strong | `default` | 1 |
| `jdbc_url_password` | JDBC URL password | strong | `default` | 1 |
| `docker_registry_auth` | Docker registry auth | strong | `default` | 1 |
| `vault_token` | Vault token | strong | `default` | 1 |
| `url_credentials` | URL with embedded credentials | weak | `default` | 1 |
| `http_bearer_token` | HTTP bearer token | weak | `default` | 1 |
| `env_assignment` | Secret-looking assignment | weak | `default` | 1 |
| `multiline_credential` | Multi-line structured credential | weak | `default` | 1 |

Custom patterns are not listed because this catalogue is generated from compiled-in rules only.

## `aws_access_key_id`

- **Label:** AWS access key ID
- **Confidence:** strong
- **Pack:** `default` version 1
- **Rotation guidance:** https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html

Matches `AKIA` or `ASIA` followed by 16 uppercase base32-style characters. Those are the access-key prefixes, and a structural check rejects a tail made from one repeated character so redactions, banners, and placeholders do not fire.

## `aws_principal_id`

- **Label:** AWS principal ID (identifier, not a credential)
- **Confidence:** weak
- **Pack:** `default` version 1
- **Rotation guidance:** no provider page — AWS principal IDs are identifiers, not credentials, so there is nothing to rotate.

Matches the `AGPA`, `AIDA`, `AROA`, `AIPA`, `ANPA`, `ANVA`, and `APKA` identifier prefixes followed by 16 or 17 uppercase base32-style characters, rejecting a tail made from one repeated character. It is weak and separate because these are identifiers rather than credentials and full-length values appear in ordinary `aws sts get-caller-identity` and IAM output.

## `aws_secret_access_key`

- **Label:** AWS secret access key
- **Confidence:** strong
- **Pack:** `default` version 1
- **Rotation guidance:** https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html

Matches exactly 40 base64 characters only beside the AWS secret access key name, because a bare 40-character base64 run would cause false positives.

## `github_token`

- **Label:** GitHub token
- **Confidence:** strong
- **Pack:** `default` version 1
- **Rotation guidance:** https://docs.github.com/authentication/keeping-your-account-and-data-secure/token-expiration-and-revocation

Matches a `ghp_`, `gho_`, `ghu_`, `ghs_`, or `ghr_` prefix followed by at least 36 alphanumeric characters.

## `github_pat`

- **Label:** GitHub fine-grained token
- **Confidence:** strong
- **Pack:** `default` version 1
- **Rotation guidance:** https://docs.github.com/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens

Matches `github_pat_`, an alphanumeric component of at least 22 characters, an underscore, and an alphanumeric component of at least 59 characters. GitHub states that its tokens will grow in length, so both components are minimums and a longer token is reported whole rather than truncated and discarded.

## `anthropic_api_key`

- **Label:** Anthropic API key
- **Confidence:** strong
- **Pack:** `default` version 1
- **Rotation guidance:** https://console.anthropic.com/settings/keys

Matches `sk-ant-` followed by at least 32 characters from the alphanumeric, underscore, and hyphen alphabet.

## `openai_api_key`

- **Label:** OpenAI API key
- **Confidence:** strong
- **Pack:** `default` version 1
- **Rotation guidance:** https://platform.openai.com/api-keys

Matches `sk-proj-`, `sk-svcacct-`, or `sk-admin-` followed by at least 20 full-alphabet characters, or `sk-` followed by exactly 48 alphanumeric characters. Requiring the complete token alphabet keeps prose such as `sk-learn` and `sk-ms-version` out.

## `stripe_secret_key`

- **Label:** Stripe live secret key
- **Confidence:** strong
- **Pack:** `default` version 1
- **Rotation guidance:** https://dashboard.stripe.com/apikeys

Matches only live `sk_live_` and `rk_live_` keys followed by at least 20 alphanumeric characters. Test keys are deliberately excluded because they live in public documentation, CI fixtures, and sample apps, and firing on them would be cry-wolf noise.

## `slack_token`

- **Label:** Slack token
- **Confidence:** strong
- **Pack:** `default` version 1
- **Rotation guidance:** https://api.slack.com/authentication/rotation

Matches `xoxb-`, `xoxa-`, `xoxp-`, `xoxr-`, or `xoxs-` followed by at least 12 alphanumeric or hyphen characters.

## `google_api_key`

- **Label:** Google API key
- **Confidence:** strong
- **Pack:** `default` version 1
- **Rotation guidance:** https://console.cloud.google.com/apis/credentials

Matches `AIza` followed by exactly 35 characters from the alphanumeric, underscore, and hyphen alphabet.

## `google_oauth_client_secret`

- **Label:** Google OAuth client secret
- **Confidence:** strong
- **Pack:** `default` version 1
- **Rotation guidance:** https://console.cloud.google.com/apis/credentials

Matches `GOCSPX-` followed by exactly 28 characters from the alphanumeric, underscore, and hyphen alphabet; the prefix is what makes the rule precise enough to ship.

## `jwt`

- **Label:** JSON Web Token
- **Confidence:** strong
- **Pack:** `default` version 1
- **Rotation guidance:** no provider page — JWT issuers control revocation, so the correct action depends on whoever issued the token.

Matches three sufficiently long base64url segments beginning with `eyJ`, then fires only when the header segment base64url-decodes to a JSON object carrying a string `alg`. Version strings, file names, and base64 blobs that merely contain two dots are rejected.

## `private_key_block`

- **Label:** Private key block
- **Confidence:** strong
- **Pack:** `default` version 1
- **Rotation guidance:** no provider page — Private keys have no single provider; replace or revoke trust wherever the corresponding public key is authorized.

Matches a private-key opening marker and, when present, its body and closing marker. The closing block is optional so a key cut off by the pane's line budget still reports.

## `slack_webhook_url`

- **Label:** Slack webhook URL
- **Confidence:** strong
- **Pack:** `default` version 1
- **Rotation guidance:** https://api.slack.com/apps

Matches the Slack webhook host and services path followed by three alphanumeric path components of at least 8, 8, and 20 characters.

## `npm_token`

- **Label:** npm access token
- **Confidence:** strong
- **Pack:** `default` version 1
- **Rotation guidance:** https://www.npmjs.com/settings/~/tokens

Matches `npm_` or `npms_` followed by at least 36 alphanumeric characters. npm's own redactor covers both prefixes and a body of 36 to 48 characters, so the rule treats the length as a minimum and reports a longer body whole rather than matching its first 36 characters and then discarding the finding as part of a longer token.

## `pypi_token`

- **Label:** PyPI API token
- **Confidence:** strong
- **Pack:** `default` version 1
- **Rotation guidance:** https://pypi.org/manage/account/token/

Matches `pypi-AgEIcHlwaS5vcmc` followed by at least 40 characters from the alphanumeric, underscore, and hyphen alphabet.

## `sendgrid_api_key`

- **Label:** SendGrid API key
- **Confidence:** strong
- **Pack:** `default` version 1
- **Rotation guidance:** https://app.sendgrid.com/settings/api_keys

Matches `SG.`, a 22-character component, a dot, and a 43-character component, with both components restricted to the alphanumeric, underscore, and hyphen alphabet.

## `gitlab_pat`

- **Label:** GitLab personal access token
- **Confidence:** strong
- **Pack:** `default` version 1
- **Rotation guidance:** https://docs.gitlab.com/user/profile/personal_access_tokens/

Matches `glpat-` followed by at least 20 characters from the alphanumeric, underscore, and hyphen alphabet.

## `grafana_service_account_token`

- **Label:** Grafana service account token
- **Confidence:** strong
- **Pack:** `default` version 1
- **Rotation guidance:** https://grafana.com/docs/grafana/latest/administration/service-accounts/

Matches the `glsa_` prefix, a 32-character alphanumeric body, and an eight-character lowercase hexadecimal checksum separated by an underscore. Grafana's own generator is the source of the checksum algorithm; the rule recomputes its IEEE CRC-32 and little-endian encoding, so a string of the right shape with the wrong checksum does not fire.

## `huggingface_token`

- **Label:** Hugging Face token
- **Confidence:** strong
- **Pack:** `default` version 1
- **Rotation guidance:** https://huggingface.co/settings/tokens

Matches `hf_` followed by at least 34 alphanumeric characters.

## `age_secret_key`

- **Label:** age secret key
- **Confidence:** strong
- **Pack:** `default` version 1
- **Rotation guidance:** no provider page — age keys have no provider or revocation service; replace the recipient wherever the public key is trusted.

Matches the private half of an age keypair: `AGE-SECRET-KEY-1` followed by exactly 58 Bech32 characters. The public `age1` recipient is deliberately excluded because it is not a secret, and the body omits `1`, `B`, `I`, and `O` as required by that alphabet.

## `jdbc_url_password`

- **Label:** JDBC URL password
- **Confidence:** strong
- **Pack:** `default` version 1
- **Rotation guidance:** no provider page — The database provider is not encoded in a JDBC password, so rotation depends on the database that issued it.

Matches a password carried in a JDBC connection string, either as a `?password=` or `&password=` query parameter or as a `;password=` property. The literal `jdbc:` scheme is the anchor: without it this would be a generic `password=` matcher, which would fire on ordinary query strings and log lines. The value still has to survive the placeholder filter, so `password=${DB_PASS}` and `password=changeme` stay quiet.

## `docker_registry_auth`

- **Label:** Docker registry auth
- **Confidence:** strong
- **Pack:** `default` version 1
- **Rotation guidance:** no provider page — The registry is not encoded in Docker auth metadata, so rotation depends on the registry that issued the credential.

Matches the `"auth"` field of a Docker registry credential, which holds base64 of `username:password`. The base64 is decoded and has to contain exactly one `:` with a password half that looks like a credential; without that check the rule would fire on pasted image layers and on any base64 that happens to sit next to the word `auth`.

## `vault_token`

- **Label:** Vault token
- **Confidence:** strong
- **Pack:** `default` version 1
- **Rotation guidance:** https://developer.hashicorp.com/vault/docs/commands/token/revoke

Matches the `hvs.`, `hvb.` and `hvr.` token prefixes followed by at least 24 characters. The legacy `s.` form is deliberately excluded: two characters of prefix, one of them a full stop, cannot carry a strong claim, and prose beginning `s.` is ordinary output.

## `url_credentials`

- **Label:** URL with embedded credentials
- **Confidence:** weak
- **Pack:** `default` version 1
- **Rotation guidance:** no provider page — The URL can refer to any issuer, so rotation depends on the service that issued the password.

Matches only the password portion of a scheme-based URL containing user information. It is weak because connection-string examples commonly have this shape, and the password must pass the placeholder filter.

## `http_bearer_token`

- **Label:** HTTP bearer token
- **Confidence:** weak
- **Pack:** `default` version 1
- **Rotation guidance:** no provider page — Bearer tokens have no provider-specific shape, so revocation depends on whoever issued the token.

Matches at least 16 credential-alphabet characters following an `Authorization: Bearer` header. It is weak because agents commonly print that header in curl commands, and the captured token must pass the placeholder filter.

## `env_assignment`

- **Label:** Secret-looking assignment
- **Confidence:** weak
- **Pack:** `default` version 1
- **Rotation guidance:** no provider page — Generic assignments do not identify an issuer, so rotation depends on whoever issued the credential.

Matches secret-looking shell assignments and YAML or JSON-style mappings anchored at the start of a line. It requires a secret-ish name segment, rejects a bare `*_KEY` because names such as `GPG_KEY` and `CACHE_KEY` are ordinary output, and drops placeholder values. The mapping form requires whitespace after the colon so ARN and URL text does not fire.

## `multiline_credential`

- **Label:** Multi-line structured credential
- **Confidence:** weak
- **Pack:** `default` version 1
- **Rotation guidance:** no provider page — Multi-line credential shapes do not identify an issuer, so rotation depends on whoever issued the credential.

Matches a credential-shaped key whose value continues onto following lines, as a GCP service-account key, a Kubernetes secret manifest or a YAML block scalar prints one. The key must pass the same secret-ish name test the single-line assignment rule uses, the join is bounded to eight continuation lines and 4096 characters, and the joined value still has to survive the placeholder filter. It is weak because a key-and-value line is the shape of almost all structured output; where the joined value turns out to be something a strong rule validates on its own merits, that rule reports it instead. A bare `auth` key deliberately cannot start a join, because `AUTH` is a key qualifier rather than a secret-ish name and the single-line Docker rule already covers that shape.

## Formats considered but not shipped

These credential formats were considered and deliberately not shipped because precision is the product: an imprecise rule breaks the scanner's only promise.

| Format | Marker | Reason |
| --- | --- | --- |
| GitLab pipeline trigger token | `glptt-` | The prefix is documented but no provider-controlled source establishes the body's length or charset. |
| GitLab runner authentication token | `glrt-` | The prefix is documented but no provider-controlled source establishes the body's length or charset. |
| GitLab runner authentication token created via registration token | `glrtr-` | The prefix is documented but no provider-controlled source establishes the body's length or charset. |
| GitLab deploy token | `gldt-` | The prefix is documented but no provider-controlled source establishes the body's length or charset. |
| GitLab SCIM token | `glsoat-` | The prefix is documented but no provider-controlled source establishes the body's length or charset. |
| GitLab incoming mail token | `glimt-` | The prefix is documented but no provider-controlled source establishes the body's length or charset. |
| GitLab OAuth application secret | `gloas-` | The prefix is documented but no provider-controlled source establishes the body's length or charset. |
| DigitalOcean personal access token | `dop_v1_` | The prefix is documented but no provider-controlled source establishes the body's length or charset. |
| DigitalOcean OAuth access token | `doo_v1_` | The prefix is documented but no provider-controlled source establishes the body's length or charset. |
| DigitalOcean OAuth refresh token | `dor_v1_` | The prefix is documented but no provider-controlled source establishes the body's length or charset. |
| Slack app-level token | `xapp-` | The prefix is documented but no provider-controlled source establishes the body's length or charset. |
| Shopify Admin API access token | `shpat_` | The provider documents the value as opaque, and no provider-controlled source establishes the body's length or charset. |
| Shopify delegate access token | `shppa_` | The provider documents the value as opaque, and no provider-controlled source establishes the body's length or charset. |
| Shopify custom app access token | `shpca_` | The provider documents the value as opaque, and no provider-controlled source establishes the body's length or charset. |
| Shopify app secret | `shpss_` | The provider documents the value as opaque, and no provider-controlled source establishes the body's length or charset. |
| Atlassian API token | `ATATT` | The body length and charset appear only in third-party scanner rules, not a provider-controlled source. |
| Postman API key | `PMAK-` | The body length and charset appear only in third-party scanner rules, not a provider-controlled source. |
| SonarQube project analysis token | `sqp_` | The body length and charset appear only in third-party scanner rules, not a provider-controlled source. |
| SonarQube user token | `squ_` | The body length and charset appear only in third-party scanner rules, not a provider-controlled source. |
| SonarQube global analysis token | `sqa_` | The body length and charset appear only in third-party scanner rules, not a provider-controlled source. |
| Supabase personal access token | `sbp_` | The body length and charset appear only in third-party scanner rules, not a provider-controlled source. |
| Databricks personal access token | `dapi` | The body length and charset appear only in third-party scanner rules, not a provider-controlled source. |
| Docker Hub personal access token | `dckr_pat_` | The body length and charset appear only in third-party scanner rules, not a provider-controlled source. |
| New Relic user API key | `NRAK-` | The prefix mapping, body length, and charset appear only in third-party scanner rules, not a provider-controlled source. |
| New Relic browser key | `NRJS-` | The prefix mapping, body length, and charset appear only in third-party scanner rules, not a provider-controlled source. |
| New Relic ingest license key | `NRII-` | The prefix mapping, body length, and charset appear only in third-party scanner rules, not a provider-controlled source. |
| Linear API key | `lin_api_` | The body length and charset appear only in third-party scanner rules, not a provider-controlled source. |
| Figma personal access token | `figd_` | The body length and charset appear only in third-party scanner rules, not a provider-controlled source. |
| Groq API key | `gsk_` | The body length and charset appear only in third-party scanner rules, not a provider-controlled source. |
| Replicate API token | `r8_` | The body length and charset appear only in third-party scanner rules, not a provider-controlled source. |
| Perplexity API key | `pplx-` | The body length and charset appear only in third-party scanner rules, not a provider-controlled source. |
| OpenRouter API key | `sk-or-v1-` | The body length and charset appear only in third-party scanner rules, not a provider-controlled source. |
| Doppler personal token | `dp.pt.` | The provider documents the prefix and scope segment, but the body length appears only in third-party scanner rules. |
| Doppler service token | `dp.st.` | The provider documents the prefix and scope segment, but the body length appears only in third-party scanner rules. |
| Doppler service account token | `dp.sa.` | The provider documents the prefix and scope segment, but the body length appears only in third-party scanner rules. |
| Doppler CLI token | `dp.ct.` | The provider documents the prefix and scope segment, but the body length appears only in third-party scanner rules. |
| Doppler SCIM token | `dp.scim.` | The provider documents the prefix and scope segment, but the body length appears only in third-party scanner rules. |
| Terraform Cloud API token | `.atlasv1.` | The fixed marker is an infix, not a prefix. |
| Fly.io authorization token | `FlyV1` | The marker is ordinary text and the body has no invariant length. |
| Fly.io deploy token with fm1r marker | `fm1r_` | The marker is ordinary text and the body has no invariant length. |
| Fly.io deploy token with fm2 marker | `fm2_` | The marker is ordinary text and the body has no invariant length. |
| JFrog reference token | — | The 64-character value has no provider-assigned prefix or provider-controlled charset. |
| Azure Storage account key | `AccountKey=` | The provider documents the key value as opaque. |
| Telegram bot token | — | There is no invariant tail length because the bot identifier width changes. |
| Discord bot token | — | The documented segment lengths are examples, not provider-guaranteed invariants. |
| Square access token | `EAAA` | The body varies from 22 to 60 characters, so the prefix does not establish a precise shape. |
| Mailgun API key | `key-` | The marker is a short English word and no provider-controlled source establishes the body grammar. |
| Airtable personal access token | — | The provider documents the value as opaque and advises against pattern matching. |
| Notion integration token | `ntn_` | The provider documents the value as opaque and advises against pattern matching. |
| Grafana Cloud access policy token | `glc_` | The marker names a token and is not part of the secret value. |
| OpenAI organization identifier | `org-` | This value is an identifier rather than a credential. |
| Datadog API key | — | There is no provider-assigned prefix at all. |
| Segment write key | — | There is no provider-assigned prefix at all. |
| Vercel access token | — | There is no provider-assigned prefix at all. |
| Netlify personal access token | — | There is no provider-assigned prefix at all. |
| Render API key | — | There is no provider-assigned prefix at all. |
| Railway API token | — | There is no provider-assigned prefix at all. |
| Heroku API key | — | There is no provider-assigned prefix at all. |
| Postmark server token | — | There is no provider-assigned prefix at all. |
| Twitch client secret | — | There is no provider-assigned prefix at all. |
| Asana personal access token | — | There is no provider-assigned prefix at all. |
| Mistral API key | — | There is no provider-assigned prefix at all. |
| Together AI API key | — | There is no provider-assigned prefix at all. |
| Cohere API key | — | There is no provider-assigned prefix at all. |
| DeepSeek API key | — | There is no provider-assigned prefix at all. |
| Stripe test secret key | `sk_test_` | Test keys live in public documentation, CI fixtures, and sample apps, and leaking one costs nothing, so firing on them is pure cry-wolf. |
| Stripe test restricted key | `rk_test_` | Test keys live in public documentation, CI fixtures, and sample apps, and leaking one costs nothing, so firing on them is pure cry-wolf. |
| Twilio auth token | — | The AC and SK SIDs are identifiers rather than secrets, while the auth token is 32 bare hex characters indistinguishable from a git blob identifier. |
| Cloudflare API token | — | The value is 40 characters of alphanumeric, underscore, and hyphen characters with no prefix. |
| Generic high-entropy key | — | Generic 32- or 40-character hex or base64 keys have no provider-specific context. |

