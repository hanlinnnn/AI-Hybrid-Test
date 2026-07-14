/**
 * Semgrep-based target discovery.
 *
 * Runs Semgrep rules against the repository, parses SARIF output,
 * and returns discovered targets with inline prompt enrichment.
 */

import { runSemgrep } from '../semgrep-runner.js';
import { parseSARIF, deduplicateTargets } from '../sarif-parser.js';
import { logDebug } from '../logging.js';
import { buildSarifTargetPromptEnrichment } from './sarif-target-enrichment.js';
import { DEFAULT_GENERIC_PROMPT } from '../defaults.js';
import type { TargetDiscovery, DiscoveredTarget, DiscoveryOptions } from '../discovery.js';
import type { SecurityCheck } from '../types.js';

const TAG = 'semgrep-discovery';

export const semgrepDiscovery: TargetDiscovery = {
  name: 'semgrep',
  defaultGenericPrompt: DEFAULT_GENERIC_PROMPT,
  needsInstructions: true,
  supportsDiffFilter: true,

  async discover(
    check: SecurityCheck,
    repoPath: string,
    _options?: DiscoveryOptions,
  ): Promise<DiscoveredTarget[]> {
    const checkTarget = check.checkTarget!;

    logDebug(TAG, `Running Semgrep for check: ${check.id}`);

    const sarifContent = await runSemgrep({
      repositoryPath: repoPath,
      rules: checkTarget.rules,
      config: checkTarget.config,
    });

    let targets = parseSARIF(sarifContent);
    targets = deduplicateTargets(targets);

    logDebug(TAG, `Discovered ${targets.length} targets`);

    return targets.map((target, idx) => ({
      file: target.file,
      startLine: target.startLine,
      endLine: target.endLine,
      label: `[target ${idx + 1}/${targets.length}]`,
      message: target.message,
      snippet: target.snippet,
      promptEnrichment: buildSarifTargetPromptEnrichment(target.file, target.startLine, target.endLine),
    }));
  },
};
