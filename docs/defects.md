# Defects - jupyterlab_passkey_extension

Defects in the passkey bridge: the relay between the Jupyter server and local clients, the browser dialogs, the CLI's reporting of ceremony results, and the password vault and its panel.

## Authors

- `@kj` Konrad Jelen

## Relay backend `RELAY`

keyctl and /dev/shm relay between the Jupyter server and the CLI

- [x] `DEF-RELAY-1` **keyctl reported unavailable while installed** - MEDIUM; `passphrase` printed `keyctl unavailable; using /dev/shm relay ... install keyutils` with keyctl in /usr/bin and /opt/conda/bin; the relay fell back to shm; cause: `@u` not possessed; fix: the probe links `@u` into `@s`, the warning names the cause; `relay.py`
  - evidence: `test_probe_possesses_the_user_keyring_before_testing_it`, `test_probe_detail_names_possession_on_read_denied` green, pytest 193/193 2026-09-26 v1.0.44; field host: pipe denied before the link, read after it
  - related: ACC-SELECT-5 - the criterion this violated
  - repro: in a JupyterLab terminal, run `jupyterlab-passkey passphrase`; stderr says keyctl unavailable
  - test-tags: UNIT, MANUAL
  - root-cause: 2026-09-26T14:29:49Z @kj a `user` key grants read only to a possessor; processes started without `pam_keyinit` (docker exec, JupyterLab terminal) do not have `@u` linked into `@s`, so `keyctl pipe` fails with EACCES and the probe falls back
  - log: 2026-09-26T14:29:49Z @kj added
  - log: 2026-09-26T14:29:50Z @kj reported 2026-08-04: warning said install keyutils with keyctl installed; `keyctl pipe` returned `Permission denied` after `padd` and `search` succeeded
  - log: 2026-09-26T14:29:50Z @kj closed: fixed in v1.0.43: `_keyctl_probe` runs `keyctl link @u @s` first; warning names the failing step; `--debug` added

## Passphrase dialog `PASS`

The browser passphrase dialog and the CLI waiting on it

- [x] `DEF-PASS-2` **dismissed passphrase dialog leaves the CLI waiting** - MEDIUM; dismissing the dialog left `jupyterlab-passkey passphrase` polling until its 120s timeout; cause: the cancel was never sent to the CLI; fix: cancel stages a `cancel` relay marker and `_wait` exits `cancelled` at once; `src/passphrase.ts`, `routes.py`, `cli.py`
  - evidence: `test_wait_ends_at_once_on_a_cancel_marker`, `test_passphrase_cancel_stages_a_marker_not_a_secret` green, pytest 193/193 2026-09-26 v1.0.44; jest `signals the cancel without ever relaying the passphrase` green, jest 62/62 2026-09-26 v1.0.44
  - repro: run `jupyterlab-passkey passphrase`, click the notification, dismiss the dialog; the CLI waits 120s
  - test-tags: UNIT
  - root-cause: 2026-09-26T14:29:50Z @kj the dialog returned on dismiss without writing to the relay, the CLI's only channel from the browser, so `_wait` polled to its timeout
  - log: 2026-09-26T14:29:50Z @kj added
  - log: 2026-09-26T14:29:50Z @kj reported 2026-08-04: dismissing the password window does not end `jupyterlab-passkey passphrase`
  - log: 2026-09-26T14:29:50Z @kj closed: fixed in v1.0.43: `runPassphrase` POSTs `cancelled: true`; the handler stages a secret-free `cancel` marker (TTL 60s); `_wait(watch_cancel=True)` exits

## Ceremony errors `ERROR`

How a failed WebAuthn ceremony is reported to the CLI

- [x] `DEF-ERROR-3` **RP ID and URL mismatch reported as a bare error** - MEDIUM; a ceremony whose `--rp-id` did not match the tab URL printed `ceremony failed: error`; cause: `SecurityError` mapped to `error`; fix: mapped to `rp-id-mismatch`, the CLI names `--rp-id` against the tab hostname; `src/passkey-util.ts`, `cli.py`
  - evidence: `test_rp_id_mismatch_gives_an_actionable_message` green, pytest 193/193 2026-09-26 v1.0.44; jest `maps a SecurityError to rp-id-mismatch, the fixable URL case` green, jest 62/62 2026-09-26 v1.0.44
  - repro: open JupyterLab on one host, run `jupyterlab-passkey get --rp-id <another host>`, click; the CLI prints `ceremony failed: error`
  - test-tags: UNIT
  - root-cause: 2026-09-26T14:29:50Z @kj `mapCeremonyError` turned every exception except `NotAllowedError` into `error`, including the `SecurityError` WebAuthn throws when the RP ID is not the tab's host or a parent domain of it
  - log: 2026-09-26T14:29:50Z @kj added
  - log: 2026-09-26T14:29:50Z @kj reported 2026-08-04: a ceremony with a different URL fails with no usable message in the CLI
  - log: 2026-09-26T14:29:50Z @kj closed: fixed in v1.0.44: `SecurityError` -> `rp-id-mismatch` with an actionable CLI message; other DOMExceptions pass as `error: <name>`

## Vault `VAULT`

The vault server side, CLI and Python API

- [x] `DEF-VAULT-4` **Two vaults under one user share the unlocked key** - MAJOR; unlocking vault B made vault A answer 'the vault entries do not decrypt'; B's lock also locked A; two labs or a second JLAB_PASSKEY_VAULT under one uid
  - evidence: store.create writes a random 16-hex id; holders take vault_id on put/get/clear/remaining; test_two_vaults_under_one_user_never_share_the_unlocked_key, test_a_key_is_only_ever_read_back_for_its_own_vault, test_keyctl_keeps_one_key_per_vault green, pytest 388/388 2026-09-26 v1.0.47
  - repro: two services with separate JLAB_PASSKEY_VAULT on keyctl; unlock B; read from A
  - test-tags: UNIT
  - root-cause: 2026-09-26T16:40:12Z @kj the holder stored the key under one fixed name per uid (keyctl) or per XDG_STATE_HOME (gpg-agent), not per vault
  - log: 2026-09-26T16:40:12Z @kj added
  - log: 2026-09-26T16:40:38Z @kj closed
- [x] `DEF-VAULT-5` **Passkey add on a locked vault leaves an unused passkey** - MAJOR; vault passkey add ran create, confirm and get before the server answered 423; the new credential stayed in the authenticator with no slot; vault recovery asked for the passphrase twice before failing
  - evidence: since the proof change neither command needs an unlock: passkey add and recovery take a proof, so a locked vault never answers 423 after the browser step; test_passkey_add_needs_no_unlock, test_recovery_needs_the_current_passphrase_not_an_unlock green, pytest 412/412 2026-09-27
  - repro: vault lock; vault passkey add
  - test-tags: UNIT
  - root-cause: 2026-09-26T16:40:12Z @kj neither command checked the lock before the browser step or the prompt
  - log: 2026-09-26T16:40:12Z @kj added
  - log: 2026-09-26T16:40:38Z @kj closed
  - log: 2026-09-27T02:40:44Z @kj edited evidence "cmd_passkey_add and cmd_recovery unlock first; test_passkey_add_unlocks_before_the_browser_creates_a_passkey, test_recovery_unlocks_before_asking_for_the_new_passphrase green, pytest 388/388 2026-09-26 v1.0.47" -> "since the proof change neither command needs an unlock: passkey add and recovery take a proof, so a locked vault never answers 423 after the browser step; test_passkey_add_needs_no_unlock, test_recovery_needs_the_current_passphrase_not_an_unlock green, pytest 412/412 2026-09-27"
- [x] `DEF-VAULT-6` **Generated passwords misread from the Show image** - MAJOR; the generator drew l I 1 | O 0, which the distorted Show image renders alike; about two in three 24-character passwords held one
  - evidence: generator alphabet leaves out l I 1 | O 0; test_generated_passwords_leave_out_characters_that_look_alike green (200 draws), pytest 388/388 2026-09-26 v1.0.47
  - repro: vault generate; vault show the entry; compare l, I, 1 and |
  - test-tags: UNIT
  - root-cause: 2026-09-26T16:40:13Z @kj the alphabet was all ASCII letters and digits plus symbols including |
  - log: 2026-09-26T16:40:13Z @kj added
  - log: 2026-09-26T16:40:38Z @kj closed
- [x] `DEF-VAULT-13` **Loopback requests went through http_proxy** - MAJOR; urlopen followed http_proxy for 127.0.0.1, so the vault client sent the Jupyter token and new passwords to the proxy; the bridge trigger sent the token
  - evidence: cli._LOOPBACK opener with an empty ProxyHandler serves client.request and _trigger; test_requests_to_the_local_server_never_go_through_a_proxy green (fails with a proxy-honouring opener), pytest 394/394 2026-09-26
  - repro: export http_proxy=http://proxy:3128; jupyterlab-passkey vault add x
  - test-tags: UNIT
  - root-cause: 2026-09-26T17:18:30Z @kj urllib.request.urlopen builds its opener from the proxy environment and has no loopback exemption without no_proxy
  - log: 2026-09-26T17:18:30Z @kj added
  - log: 2026-09-26T17:18:36Z @kj closed

## Vault panel `PANEL`

The vault sidebar panel, its dialogs and styles

- [x] `DEF-PANEL-7` **Panel buttons unreadable in dark themes** - CRITICAL; secondary buttons kept the browser's light face under light theme text, about 1.5:1; the Notes field was a white box; disabled Unlock with passkey looked enabled
  - evidence: button rules at specificity above button.jp-mod-styled, face --jp-layout-color3, disabled 0.6 opacity, Notes field styled; screenshots of the list, locked view, form and cog in JupyterLab Light, JupyterLab Dark and Galaxa Dark Theme - Steel checked 2026-09-26 v1.0.48; Galata 35/35
  - repro: open the vault panel in JupyterLab Dark or Galaxa Dark Theme - Steel; expand an entry
  - test-tags: MANUAL
  - root-cause: 2026-09-26T16:40:21Z @kj the panel rule lost to the lab's button.jp-mod-styled on specificity and set no background; outside a dialog the lab supplies none
  - log: 2026-09-26T16:40:21Z @kj added
  - log: 2026-09-26T16:47:08Z @kj closed
- [x] `DEF-PANEL-8` **Entries unreachable from the keyboard** - MAJOR; the row header was a div with a click listener only, so Copy, Show, Edit and Delete were out of reach; every action re-render dropped focus to the page body
  - evidence: row header is a button with aria-expanded; focus restored by data-focus-key after render; jest 'opens a row from the keyboard and keeps focus through a render' green, jest 105/105 2026-09-26 v1.0.47
  - repro: Tab through the unlocked panel; no row takes focus
  - test-tags: UNIT
  - root-cause: 2026-09-26T16:40:21Z @kj no button or tabindex on the row header; render replaced the focused button and nothing restored focus
  - log: 2026-09-26T16:40:21Z @kj added
  - log: 2026-09-26T16:40:38Z @kj closed
  - log: 2026-09-26T20:37:30Z @kj evidence tests replaced by the entry popup redesign (ACC-PANEL-157, 158): the row is a button that opens the popup, jest 'opens the entry in its popup, and Edit there opens Edit entry for it'
- [x] `DEF-PANEL-9` **Double-click on Delete deletes the entry** - MAJOR; arming re-rendered Confirm delete in the same place, so the second click of a double-click confirmed; the unarmed button was already filled red, so arming changed only the label
  - evidence: confirm ignores clicks within ARM_DELAY_MS (500) of arming; unarmed Delete is an outline; jest 'deletes only on a second, separate click - never on a double-click' green, jest 105/105 2026-09-26 v1.0.47
  - repro: expand an entry; double-click Delete
  - test-tags: UNIT
  - root-cause: 2026-09-26T16:40:21Z @kj the confirm step accepted any second click, and the armed and unarmed styles matched
  - log: 2026-09-26T16:40:21Z @kj added
  - log: 2026-09-26T16:40:38Z @kj closed
  - log: 2026-09-26T20:37:32Z @kj evidence test replaced: entry Delete moved to the popup with a confirm dialog (ACC-PANEL-159), jest 'asks before deleting from the popup, and keeps the entry when that is declined'
- [x] `DEF-PANEL-10` **Entry form fields had no visible labels** - MAJOR; every field was labelled by its placeholder only; in Edit the fields were filled, so none showed; the keep-the-password rule vanished on typing
  - evidence: visible label per field (for/id), help line via aria-describedby; jest 'labels every field visibly and says an empty password keeps the old one' green, jest 105/105; Galata add-entry test fills fields by label 2026-09-26 v1.0.47
  - repro: Edit an entry whose username and category hold the same word
  - test-tags: UNIT, E2E
  - root-cause: 2026-09-26T16:40:27Z @kj placeholders stood in for labels
  - log: 2026-09-26T16:40:27Z @kj added
  - log: 2026-09-26T16:40:38Z @kj closed
  - log: 2026-09-26T20:37:33Z @kj evidence test replaced: jest 'shows Edit with the same visible fields as Add, the name read-only, plus the keep-password help' checks the visible labels
- [x] `DEF-PANEL-11` **Passkeys on one host cannot be told apart** - MAJOR; the panel always registered with an empty label, so every row read the hostname twice; the OS passkey manager listed identical 'jupyterlab-vault' credentials
  - evidence: confirm dialog asks for a name (default hostname), stored as the slot label; user.name carries host and date; jest 'stores the name chosen in the confirm step' green, jest 105/105 2026-09-26 v1.0.47
  - repro: register two passkeys from one host; open the cog
  - test-tags: UNIT
  - root-cause: 2026-09-26T16:40:27Z @kj no name was asked for, and user.name was a constant
  - log: 2026-09-26T16:40:27Z @kj added
  - log: 2026-09-26T16:40:38Z @kj closed
- [x] `DEF-PANEL-12` **Security view signals contradict each other** - MAJOR; a restart that locks the vault was coloured as a warning; strong, reduced and basic named no scale; holder names were unexplained; warning text was 2.7:1 on white
  - evidence: only weakening gaps get the warning accent (survives_restart excluded); Protection states what it counts plus the container caveat; holder names explained; text stays font-color1; jest 'marks only the missing protections that weaken it', 'states what each protection level counts' green 2026-09-26 v1.0.47
  - repro: open the cog with the memory holder or keyctl
  - test-tags: UNIT
  - root-cause: 2026-09-26T16:40:27Z @kj every false capability used the warning colour, and the summary word stood alone
  - log: 2026-09-26T16:40:27Z @kj added
  - log: 2026-09-26T16:40:38Z @kj closed
  - log: 2026-09-26T20:37:35Z @kj evidence test replaced by the simple security view (ACC-PANEL-151, 154): jest 'marks each protection present or missing, for its colour'
- [x] `DEF-PANEL-14` **Cancelled dialogs reported success** - MAJOR; cancelling Create showed 'Vault created' with no vault; cancelling Change recovery passphrase showed 'Recovery passphrase changed' though nothing changed
  - evidence: an action resolving to false reports nothing; jest 'says nothing was created when the Create dialog is cancelled', 'says nothing changed when the recovery dialog is cancelled' green, jest 110/110 2026-09-26
  - repro: open the cog, click Change recovery passphrase, press Cancel
  - test-tags: UNIT
  - root-cause: 2026-09-26T17:18:30Z @kj _act set the done line whenever the action resolved, and a cancel resolved
  - log: 2026-09-26T17:18:30Z @kj added
  - log: 2026-09-26T17:18:36Z @kj closed
- [x] `DEF-PANEL-15` **Security view named the wrong missing protection** - MAJOR; the reduced sentence said 'kept out of swap or out of core dumps, not both' for memfd_secret and mlock, which have both and lack only holder-enforced expiry
  - evidence: describeProtection names each missing protection from the capabilities; jest 'states what each protection level counts, with the container caveat' covers memfd_secret (reduced - not deleted at expiry by the holder), jest 110/110 2026-09-26
  - repro: open the cog with the memory holder
  - test-tags: UNIT
  - root-cause: 2026-09-26T17:18:30Z @kj the sentence was fixed per level instead of built from the capabilities
  - log: 2026-09-26T17:18:30Z @kj added
  - log: 2026-09-26T17:18:36Z @kj closed
  - log: 2026-09-26T20:37:36Z @kj evidence test replaced by the simple security view: the protection text comes from holders.describe(), pytest test_the_protection_names_what_it_counts_with_the_container_caveat
- [x] `DEF-PANEL-16` **Secondary buttons 2.87:1 in the Steel theme** - MAJOR; the layout-color3 button face gave grey text on slate at 2.87:1; primary and armed buttons used the inverse font colour, dark on blue or red in dark themes
  - evidence: buttons follow the design system secondary spec (layout-color1 face, layout-color3 border, font-color0 text), white text on primary and armed; screenshots of list, locked view and cog in JupyterLab Light, JupyterLab Dark and Galaxa Dark Theme - Steel checked 2026-09-26 v1.0.49; Galata 35/35
  - repro: open the vault panel in Galaxa Dark Theme - Steel; expand an entry
  - test-tags: MANUAL
  - root-cause: 2026-09-26T17:18:30Z @kj the button face did not follow the design system's secondary spec
  - log: 2026-09-26T17:18:30Z @kj added
  - log: 2026-09-26T17:32:20Z @kj closed
- [x] `DEF-PANEL-17` **Status reads without end after an expired countdown** - MAJOR; with the countdown run out and the status read failing, the panel read again from every render, about 300 requests in 400 ms, until the tab was reloaded
  - evidence: an expired countdown is marked locked before the read; jest 'reads once, not without end, when the countdown ran out and the read fails' green, and it does not finish without the fix; jest 110/110 2026-09-26
  - repro: leave the panel open past the unlock time, stop the server, click Refresh
  - test-tags: UNIT
  - root-cause: 2026-09-26T17:18:30Z @kj _renderStatus called refresh when the countdown ran out, and a failed refresh rendered with the status unchanged
  - log: 2026-09-26T17:18:30Z @kj added
  - log: 2026-09-26T17:18:36Z @kj closed
- [x] `DEF-PANEL-18` **Banner lines moved the entry list** - MAJOR; the banner sat above the list, so a success line appearing or expiring 15-30 s later shifted every entry by about one button; the next click could land on the wrong action
  - evidence: banner moved below the body, so a line shrinks the body from the bottom; jest 'puts the banner below the list, so a line that comes or goes never moves the entries' green, jest 115/115 2026-09-26
  - repro: expand an entry, click Copy username, then click where Copy password was
  - test-tags: UNIT
  - root-cause: 2026-09-26T17:49:55Z @kj the banner was in the layout flow between the status line and the list
  - log: 2026-09-26T17:49:55Z @kj added
  - log: 2026-09-26T17:49:59Z @kj closed
- [x] `DEF-PANEL-19` **Escape did not close the Show password dialog** - MAJOR; the Show dialog swallowed Escape while the other four vault dialogs close on it; the password image stayed on screen
  - evidence: openCodeImage launches through launchWithEscape, the helper the passphrase, Add, Edit and passkey-confirm dialogs use; tsc and jest 115/115 green 2026-09-26
  - repro: Show a password, press Escape
  - test-tags: MANUAL
  - root-cause: 2026-09-26T17:49:55Z @kj openCodeImage launched its hasClose:false dialog without launchWithEscape
  - log: 2026-09-26T17:49:55Z @kj added
  - log: 2026-09-26T17:49:59Z @kj closed
  - log: 2026-09-27T00:46:45Z @kj evidence code replaced: openCodeImage is gone (the panel Show button went in round 5); runShow in src/show.ts launches through launchWithEscape
- [x] `DEF-PANEL-20` **Banner far below the action it reports** - MAJOR; after the banner moved below the body, the body filled the panel, so 'Copied the password' appeared at the panel's bottom edge, about 666 px below the button
  - evidence: banner sits directly under the list in the three-theme screenshots (Galaxa Steel form shot); Galata 35/35 v1.0.51 2026-09-26
  - related: DEF-PANEL-18
  - repro: open the panel at full height, expand an entry, click Copy password
  - test-tags: MANUAL
  - root-cause: 2026-09-26T18:21:19Z @kj the body kept flex 1 1 auto, which pushed the banner after it to the bottom
  - log: 2026-09-26T18:21:19Z @kj added
  - log: 2026-09-26T19:21:35Z @kj closed
- [x] `DEF-PANEL-21` **Dialogs open with the default button focused** - MEDIUM; the entry form opens with Save focused and the passphrase dialog with Submit, so typed characters go nowhere; the body's focus call runs before Dialog's, which then focuses its default button
  - evidence: focusNodeSelector on both dialogs; Galata v1.0.59 36/36 incl. entry dialog focus in Name and submitSecret first-field focus checks
  - repro: open Add entry or Unlock with the recovery passphrase, type without clicking; nothing appears in the first field
  - test-tags: E2E
  - root-cause: 2026-09-26T19:34:14Z @kj Lumino runs the body's onAfterAttach before Dialog's; Dialog.onAfterAttach focuses _primary, the default button, unless focusNodeSelector names a body element
  - log: 2026-09-26T19:34:14Z @kj added
  - log: 2026-09-26T19:57:03Z @kj closed
- [x] `DEF-PANEL-22` **Unused-passkey line lost when the server returns** - MINOR; Create vault (or Register, when a server restart locked the vault) loses the server after the browser made the passkey; the amber line naming the unused passkey went when the server answered again, because that read found the vault changed
  - evidence: Create, Register and the recovery change pass keep to _act, and _dropStale skips a kept line; jest 'keeps the unused-passkey line when the server returns with the vault Create made, whichever read comes first' green, 179/179 2026-09-27
  - root-cause: 2026-09-27T04:20:09Z @kj the state-change drop removed every action line; the unused-passkey line reports what no vault state shows
  - repro: stop the server during Create vault's passkey step, start it, wait 15 s
  - test-tags: UNIT
  - log: 2026-09-27T02:38:29Z @kj added
  - log: 2026-09-27T03:01:18Z @kj amended text "Create vault or Register loses the server after the browser made the passkey; the amber line naming the unused passkey goes when the server answers again, because that read finds the vault changed; deferred: keeping the line across that read left stale lines in review rounds 17-19" -> "MINOR; Create vault (or Register, when a server restart locked the vault) loses the server after the browser made the passkey; the amber line naming the unused passkey goes when the server answers again, because that read finds the vault changed; deferred: keeping the line across that read left stale lines in review rounds 17-19"; reason: Register changes nothing on the server, so only a restart that locked the vault drops its line
  - log: 2026-09-27T04:20:09Z @kj closed
  - log: 2026-09-27T04:43:20Z @kj amended text "Create vault (or Register, when a server restart locked the vault) loses the server after the browser made the passkey; the amber line naming the unused passkey goes when the server answers again, because that read finds the vault changed; deferred: keeping the line across that read left stale lines in review rounds 17-19" -> "MINOR; Create vault (or Register, when a server restart locked the vault) loses the server after the browser made the passkey; the amber line naming the unused passkey went when the server answered again, because that read found the vault changed"; reason: closed in round 24; the deferral clause is in the log
  - log: 2026-09-27T04:43:20Z @kj edited test-tags "MANUAL" -> "UNIT"

