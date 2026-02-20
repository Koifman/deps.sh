import type { RiskReport } from '../types.js';

export function formatJson(report: RiskReport): string {
  return JSON.stringify({
    package: {
      name: report.package.name,
      version: report.package.version,
      ecosystem: report.package.ecosystem,
      description: report.package.description,
    },
    risk: {
      score: report.totalScore,
      level: report.level,
      signals: report.signals.map(s => ({
        name: s.name,
        score: s.score,
        maxScore: s.maxScore,
        detail: s.detail,
      })),
    },
    maintainers: report.package.maintainers,
    lastPublish: report.package.lastPublish?.toISOString() ?? null,
    dependencies: report.package.dependencies,
    weeklyDownloads: report.package.weeklyDownloads,
    installScripts: report.package.installScripts,
    vulnerabilities: report.vulnerabilities.map(v => ({
      id: v.id,
      severity: v.severity,
      summary: v.summary,
      aliases: v.aliases,
      url: `https://osv.dev/vulnerability/${v.id}`,
    })),
    github: report.github ? {
      stars: report.github.stars,
      openIssues: report.github.openIssues,
      lastCommit: report.github.lastCommit?.toISOString() ?? null,
      archived: report.github.archived,
    } : null,
    typosquatMatches: report.typosquatMatches,
  }, null, 2);
}
