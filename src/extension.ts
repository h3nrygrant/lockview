import * as vscode from 'vscode';
import * as path from 'path';
import * as cp from 'child_process';
import * as fs from 'fs';

// ─── Types mirroring Python backend JSON output ────────────────────────────────

interface Diagnostic {
  severity: 'error' | 'warning' | 'info';
  message: string;
  line_number: number;
  gate_name: string;
  rule_id: string;
  detail: string;
}

interface CoverageReport {
  module_name: string;
  total_gates: number;
  locked_gates: number;
  coverage_pct: number;
  key_bits: number;
  key_inputs: string[];
  gate_type_distribution: Record<string, number>;
  key_gate_type_distribution: Record<string, number>;
  avg_key_fanin: number;
  output_cone_coverage: number;
  per_output_coverage: Record<string, number>;
  warnings: string[];
}

interface AnalysisResult {
  ok: boolean;
  file: string;
  format: string;
  module: string;
  parse_errors: string[];
  coverage: CoverageReport;
  corruptibility: any;
  lint: {
    summary: Record<string, number>;
    diagnostics: Diagnostic[];
  };
  error?: string;
}

// ─── Coverage Tree View ────────────────────────────────────────────────────────

class CoverageTreeItem extends vscode.TreeItem {
  constructor(
    label: string,
    description?: string,
    collapsible = vscode.TreeItemCollapsibleState.None,
    iconId?: string
  ) {
    super(label, collapsible);
    if (description) this.description = description;
    if (iconId) this.iconPath = new vscode.ThemeIcon(iconId);
  }
}

class LockViewCoverageProvider implements vscode.TreeDataProvider<CoverageTreeItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<CoverageTreeItem | undefined | void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private report: AnalysisResult | null = null;

  update(result: AnalysisResult) {
    this.report = result;
    this._onDidChangeTreeData.fire();
  }

  clear() {
    this.report = null;
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(el: CoverageTreeItem) { return el; }

  getChildren(el?: CoverageTreeItem): CoverageTreeItem[] {
    if (!this.report || !this.report.ok) {
      return [new CoverageTreeItem('No analysis yet', 'open a .v or .bench file and run LockView', vscode.TreeItemCollapsibleState.None, 'info')];
    }

    const c = this.report.coverage;
    const l = this.report.lint;

    if (!el) {
      // Root items
      const coverageBar = buildBar(c.coverage_pct);
  const cr = this.report.corruptibility;
  const ecrBar = buildBar(cr ? cr.estimated_corruption_pct : 0);
  const ecrIcon = cr
    ? (cr.risk_level === 'balanced' ? 'pass' : cr.risk_level === 'high' ? 'error' : 'warning')
    : 'info';

  return [
    new CoverageTreeItem('Module', this.report.module, vscode.TreeItemCollapsibleState.None, 'symbol-namespace'),
    new CoverageTreeItem('Locking Coverage', `${c.coverage_pct}%  ${coverageBar}`, vscode.TreeItemCollapsibleState.None, coverageIcon(c.coverage_pct)),
    new CoverageTreeItem('Key Bits', `${c.key_bits}`, vscode.TreeItemCollapsibleState.None, 'key'),
    new CoverageTreeItem('Locked / Total Gates', `${c.locked_gates} / ${c.total_gates}`, vscode.TreeItemCollapsibleState.None, 'circuit-board'),
    new CoverageTreeItem('Output Cone Coverage', `${c.output_cone_coverage}%`, vscode.TreeItemCollapsibleState.None, 'eye'),
    new CoverageTreeItem('Avg Key Fanin', `${c.avg_key_fanin}`, vscode.TreeItemCollapsibleState.None, 'git-merge'),
    new CoverageTreeItem('── Corruptibility ──', undefined, vscode.TreeItemCollapsibleState.None, 'dash'),
    new CoverageTreeItem('Est. Corruption Rate', cr ? `${cr.estimated_corruption_pct}%  ${ecrBar}` : 'N/A', vscode.TreeItemCollapsibleState.None, ecrIcon),
    new CoverageTreeItem('Risk Level', cr ? cr.risk_level.toUpperCase() : 'N/A', vscode.TreeItemCollapsibleState.None, ecrIcon),
    new CoverageTreeItem('Corruptibility Detail', undefined, vscode.TreeItemCollapsibleState.Collapsed, 'list-tree'),
    new CoverageTreeItem('── Diagnostics ──', undefined, vscode.TreeItemCollapsibleState.None, 'dash'),
    new CoverageTreeItem(
      `Diagnostics  (${l.summary.error ?? 0}E ${l.summary.warning ?? 0}W ${l.summary.info ?? 0}I)`,
      undefined,
      vscode.TreeItemCollapsibleState.Expanded,
      'shield'
    ),
    new CoverageTreeItem('Per-Output Coverage', undefined, vscode.TreeItemCollapsibleState.Collapsed, 'list-tree'),
    new CoverageTreeItem('Gate Type Distribution', undefined, vscode.TreeItemCollapsibleState.Collapsed, 'pie-chart'),
  ];
}

    if (el.label === 'Per-Output Coverage') {
      return Object.entries(c.per_output_coverage).map(([out, pct]) =>
        new CoverageTreeItem(out, `${pct}%  ${buildBar(pct)}`, vscode.TreeItemCollapsibleState.None, coverageIcon(pct))
      );
    }

    if (el.label === 'Corruptibility Detail') {
  const cr = this.report?.corruptibility;
  if (!cr) return [];
  const items = cr.per_output.map((o: any) =>
    new CoverageTreeItem(
      o.output_net,
      `${(o.estimated_corruption_prob * 100).toFixed(1)}%  ${buildBar(o.estimated_corruption_prob * 100)}  ${o.has_locked_cone ? o.locked_gates_in_cone + ' locked gates' : 'NO locked gates'}`,
      vscode.TreeItemCollapsibleState.None,
      o.has_locked_cone ? (o.estimated_corruption_prob >= 0.4 ? 'pass' : 'warning') : 'error'
    )
  );
  const flags = cr.risk_flags.map((f: string) =>
    new CoverageTreeItem('⚑ ' + f.slice(0, 60) + (f.length > 60 ? '…' : ''), undefined, vscode.TreeItemCollapsibleState.None, 'warning')
  );
  return [...items, ...flags];
}

    if (el.label === 'Gate Type Distribution') {
      return Object.entries(c.gate_type_distribution).map(([gt, count]) => {
        const locked = c.key_gate_type_distribution[gt] ?? 0;
        return new CoverageTreeItem(gt, `${count} total  (${locked} locked)`, vscode.TreeItemCollapsibleState.None, 'symbol-operator');
      });
    }

    if (typeof el.label === 'string' && el.label.startsWith('Diagnostics')) {
      return l.diagnostics.map(d =>
        new CoverageTreeItem(
          `[${d.rule_id}] ${d.gate_name}`,
          d.message.slice(0, 60),
          vscode.TreeItemCollapsibleState.None,
          severityIcon(d.severity)
        )
      );
    }

    return [];
  }
}

function buildBar(pct: number): string {
  const filled = Math.round(pct / 10);
  return '█'.repeat(filled) + '░'.repeat(10 - filled);
}

function coverageIcon(pct: number): string {
  if (pct >= 60) return 'pass';
  if (pct >= 30) return 'warning';
  return 'error';
}

function severityIcon(s: string): string {
  return s === 'error' ? 'error' : s === 'warning' ? 'warning' : 'info';
}

// ─── Backend Runner ────────────────────────────────────────────────────────────

function runBackend(
  filePath: string,
  sensitivity: string,
  pythonPath: string
): Promise<AnalysisResult> {
  return new Promise((resolve, reject) => {
    const backendDir = path.join(__dirname, '..', 'backend');
    const args = ['-m', 'lockview.main', 'analyze', filePath, '--sensitivity', sensitivity];

    const proc = cp.spawn(pythonPath, args, { cwd: backendDir });
    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', (d: Buffer) => stdout += d.toString());
    proc.stderr.on('data', (d: Buffer) => stderr += d.toString());

    proc.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(`Backend exited ${code}: ${stderr}`));
        return;
      }
      try {
        resolve(JSON.parse(stdout) as AnalysisResult);
      } catch (e) {
        reject(new Error(`Failed to parse backend output: ${stdout}`));
      }
    });

    proc.on('error', reject);
  });
}

// ─── Diagnostics Publisher ─────────────────────────────────────────────────────

function publishDiagnostics(
  collection: vscode.DiagnosticCollection,
  doc: vscode.TextDocument,
  result: AnalysisResult
) {
  collection.clear();
  const diags: vscode.Diagnostic[] = [];

  for (const d of result.lint.diagnostics) {
    const line = Math.max(0, d.line_number - 1);
    const textLine = doc.lineAt(Math.min(line, doc.lineCount - 1));
    const range = new vscode.Range(
      new vscode.Position(line, textLine.firstNonWhitespaceCharacterIndex),
      new vscode.Position(line, textLine.text.length)
    );

    const severity =
      d.severity === 'error' ? vscode.DiagnosticSeverity.Error
      : d.severity === 'warning' ? vscode.DiagnosticSeverity.Warning
      : vscode.DiagnosticSeverity.Information;

    const vsDiag = new vscode.Diagnostic(range, `[${d.rule_id}] ${d.message}`, severity);
    vsDiag.source = 'LockView';
    vsDiag.code = d.rule_id;
    // Attach detail as related info
    if (d.detail) {
      vsDiag.relatedInformation = [
        new vscode.DiagnosticRelatedInformation(
          new vscode.Location(doc.uri, range),
          d.detail
        )
      ];
    }
    diags.push(vsDiag);
  }

  // Parse errors
  for (const err of result.parse_errors) {
    const range = new vscode.Range(new vscode.Position(0, 0), new vscode.Position(0, 0));
    diags.push(new vscode.Diagnostic(range, `Parse error: ${err}`, vscode.DiagnosticSeverity.Error));
  }

  collection.set(doc.uri, diags);
}

// ─── Extension Activation ──────────────────────────────────────────────────────

export function activate(context: vscode.ExtensionContext) {
  const diagnosticCollection = vscode.languages.createDiagnosticCollection('lockview');
  const coverageProvider = new LockViewCoverageProvider();
  const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBar.command = 'lockview.showCoverage';

  vscode.window.registerTreeDataProvider('lockviewCoverage', coverageProvider);

  async function analyzeDocument(doc: vscode.TextDocument) {
    const config = vscode.workspace.getConfiguration('lockview');
    const pythonPath = config.get<string>('pythonPath', 'python3');
    const sensitivity = config.get<string>('attackSensitivity', 'medium');

    statusBar.text = '$(loading~spin) LockView analyzing…';
    statusBar.show();

    try {
      const result = await runBackend(doc.fileName, sensitivity, pythonPath);

      if (!result.ok) {
        vscode.window.showErrorMessage(`LockView: ${result.error}`);
        statusBar.hide();
        return;
      }

      publishDiagnostics(diagnosticCollection, doc, result);
      coverageProvider.update(result);

      const c = result.coverage;
      const l = result.lint;
      const icon = c.coverage_pct >= 50 ? '$(shield)' : c.coverage_pct >= 20 ? '$(warning)' : '$(error)';
      statusBar.text = `${icon} LockView: ${c.coverage_pct}% locked · ${l.summary.error ?? 0}E ${l.summary.warning ?? 0}W`;
      statusBar.tooltip = `${c.locked_gates}/${c.total_gates} gates locked · ${c.key_bits} key bits · click for panel`;
      statusBar.show();

    } catch (err: any) {
      vscode.window.showErrorMessage(`LockView backend error: ${err.message}`);
      statusBar.hide();
    }
  }

  // Commands
  const analyzeCmd = vscode.commands.registerCommand('lockview.analyze', () => {
    const editor = vscode.window.activeTextEditor;
    if (!editor) { vscode.window.showWarningMessage('LockView: no active file.'); return; }
    analyzeDocument(editor.document);
  });

  const showCoverageCmd = vscode.commands.registerCommand('lockview.showCoverage', () => {
    vscode.commands.executeCommand('lockviewCoverage.focus');
  });

  const clearCmd = vscode.commands.registerCommand('lockview.clearDiagnostics', () => {
    diagnosticCollection.clear();
    coverageProvider.clear();
    statusBar.hide();
  });

  // Auto-analyze on save / open
  const onSave = vscode.workspace.onDidSaveTextDocument((doc) => {
    const cfg = vscode.workspace.getConfiguration('lockview');
    if (!cfg.get<boolean>('enableAutoAnalyze', true)) return;
    if (['.v', '.sv', '.bench'].some(ext => doc.fileName.endsWith(ext))) {
      analyzeDocument(doc);
    }
  });

  const onOpen = vscode.window.onDidChangeActiveTextEditor((editor) => {
    if (!editor) return;
    const cfg = vscode.workspace.getConfiguration('lockview');
    if (!cfg.get<boolean>('enableAutoAnalyze', true)) return;
    const doc = editor.document;
    if (['.v', '.sv', '.bench'].some(ext => doc.fileName.endsWith(ext))) {
      analyzeDocument(doc);
    }
  });

  context.subscriptions.push(
    diagnosticCollection, analyzeCmd, showCoverageCmd, clearCmd,
    statusBar, onSave, onOpen
  );
}

export function deactivate() {}
