/**
 * Download any analysis result as a formatted JSON file.
 *
 * Extracted from LogAnalysisPage.tsx - generic, not log-specific, so
 * NetworkAnalysisPage.tsx can reuse it too.
 */
export function exportReport(result: any) {
  const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `analysis-${result.result_id || 'report'}.json`
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}
