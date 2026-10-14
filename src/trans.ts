import {
  ITranslator,
  nullTranslator,
  TranslationBundle
} from '@jupyterlab/translation';

const DOMAIN = 'jupyterlab_passkey_extension';

/**
 * The extension's translation bundle, for the strings the lint rule
 * `jupyter/no-untranslated-string` names: command labels, and the dialog titles,
 * dialog button labels and aria labels written as literals. Until a plugin hands
 * over the lab's translator it is the null bundle, which returns each string as
 * written.
 */
export let trans: TranslationBundle = nullTranslator.load(DOMAIN);

/** Use the lab's translator, or the null one when the lab has none. */
export function setTranslator(translator: ITranslator | null): void {
  trans = (translator ?? nullTranslator).load(DOMAIN);
}
