import { Notification } from '@jupyterlab/apputils';

import { ServerConnection } from '@jupyterlab/services';

import { requestAPI } from './request';

export interface ICopyArgs {
  nonce: string;
  label?: string;
}

/**
 * Collect the secret a local client staged under `nonce` and put it on the
 * clipboard.
 *
 * The reverse of the other commands: nothing is captured in the page, the value
 * is fetched and delivered to the user's clipboard so they can paste it into
 * whatever asked for it. The notification carries only the nonce, so the secret
 * itself never rides through the notifications extension - which broadcasts its
 * payload to every connected socket and holds it in an in-memory queue until
 * some client drains it.
 *
 * The fetch is a one-shot consume, so the value is gone from the server the
 * moment this resolves - from there the value must reach the clipboard or the
 * user, whatever the browser does. Three rungs, each catching what the one
 * above lets fall:
 *
 * 1. Write immediately, under the click's own user activation.
 * 2. Refused (the document was not focused - DevTools, another window): retry
 *    on every return of focus and on a short tick. This lands the quick
 *    alt-tab cases, where the activation is still alive.
 * 3. Still refused once the activation is gone (Chrome only honours a write
 *    for ~5s past the last gesture, so a longer absence can never be saved by
 *    a background retry): raise a NEW notification whose button click IS a
 *    fresh gesture, and write from memory when it comes. The value never
 *    leaves the page, and nothing is lost short of closing the tab.
 *
 * The value is never logged.
 */
export async function runCopy(
  args: ICopyArgs,
  serverSettings: ServerConnection.ISettings
): Promise<void> {
  const { value } = await requestAPI<{ value: string }>(
    'secret',
    serverSettings,
    {
      method: 'POST',
      body: JSON.stringify({ nonce: args.nonce })
    }
  );

  // Chrome grants clipboard-write to the focused tab outright; Firefox wants
  // transient activation, which the notification button click supplies and the
  // local fetch above is far too quick to burn through.
  try {
    await navigator.clipboard.writeText(value);
  } catch (reason) {
    // The refusal reason, never the value: the console is the only place a
    // debugging user can see WHY a copy did not land at once.
    console.warn(`[passkey:copy] clipboard write refused: ${reason}`);
    try {
      await retryWrite(value, reason);
      console.warn('[passkey:copy] retry landed the clipboard write');
    } catch {
      console.warn(
        '[passkey:copy] retries exhausted - offering a click to finish the copy'
      );
      offerRecovery(value, args.label);
    }
  }
}

/** How long the background retry keeps trying before asking for a click. */
const RETRY_DEADLINE_MS = 15000;

/** How often to retry between focus events. */
const RETRY_TICK_MS = 2000;

/**
 * Retry the clipboard write until it lands; reject with `reason` at deadline.
 *
 * The window is short on purpose: it exists for focus BLIPS, where the click's
 * activation is still alive. Past it, no background write can ever succeed
 * again and the recovery notification is the only way forward.
 */
async function retryWrite(value: string, reason: unknown): Promise<void> {
  const deadline = Date.now() + RETRY_DEADLINE_MS;
  for (;;) {
    await nextAttempt(deadline, reason);
    try {
      await navigator.clipboard.writeText(value);
      return;
    } catch (again) {
      // Retry refusals are expected while unfocused; the loop's deadline is
      // the only thing that turns them final.
      console.warn(`[passkey:copy] retry refused: ${again}`);
    }
  }
}

/**
 * Resolve at the next worthwhile moment to try again - the window regaining
 * focus, or a tick - or reject with `reason` once the deadline has passed.
 */
function nextAttempt(deadline: number, reason: unknown): Promise<void> {
  if (Date.now() >= deadline) {
    return Promise.reject(reason);
  }
  return new Promise<void>((resolve, reject) => {
    const done = (fail: boolean) => {
      window.clearTimeout(timer);
      window.removeEventListener('focus', onFocus);
      if (fail) {
        reject(reason);
      } else {
        resolve();
      }
    };
    const timer = window.setTimeout(
      () => done(Date.now() >= deadline),
      RETRY_TICK_MS
    );
    const onFocus = () => done(false);
    window.addEventListener('focus', onFocus);
  });
}

/**
 * Raise a notification whose button finishes the copy under a fresh gesture.
 *
 * The value rides in the callback's closure - page memory only, no relay, no
 * server round trip - so it survives any absence and is gone the moment the
 * tab is. If even the fresh click's write is refused, the offer is simply
 * made again; it cannot be allowed to fail silently, because this rung is
 * the one below which there is nothing.
 */
function offerRecovery(value: string, label?: string): void {
  const message = label
    ? `The clipboard needs another click - the secret is still waiting: ${label}`
    : 'The clipboard needs another click - the secret is still waiting.';
  Notification.emit(message, 'warning', {
    autoClose: false,
    actions: [
      {
        label: 'Copy to clipboard',
        displayType: 'accent',
        callback: () => {
          navigator.clipboard.writeText(value).catch(again => {
            console.warn(`[passkey:copy] recovery write refused: ${again}`);
            offerRecovery(value, label);
          });
        }
      }
    ]
  });
}
