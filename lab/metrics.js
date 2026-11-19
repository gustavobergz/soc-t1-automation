(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.SocMetrics = factory();
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  function containmentMeans(records) {
    return Object.fromEntries(['manual', 'auto', 'llm'].map((mode) => {
      const values = records.filter((event) => event.event === 'panel.metrics' && event.mode === mode &&
        event.outcome === 'contained' && Number.isFinite(event.response_ms) && event.response_ms >= 0);
      return [mode, { count: values.length,
        meanMs: values.length ? values.reduce((sum, event) => sum + event.response_ms, 0) / values.length : null }];
    }));
  }

  function interval(from, to) {
    return Number.isFinite(from) && Number.isFinite(to) && to >= from ? Math.round(to - from) : null;
  }

  function containmentVerified(state) {
    return Boolean(state.verified && state.control && (!state.scenario || state.legitimate) &&
      typeof state.approvalId === 'string' && state.approvalId === state.blockApprovalId &&
      state.approvalId === state.requestedApprovalId);
  }

  function historicalSummary(records) {
    const metrics = records.filter((item) => item?.event === 'panel.metrics');
    const statistics = {};
    for (const mode of ['manual', 'auto', 'llm', 'failure']) {
      const rows = metrics.filter((item) => item.mode === mode);
      statistics[mode] = { count: rows.length };
      for (const key of ['detection_ms', 'triage_ms', 'response_ms']) {
        const values = rows.filter((item) => key !== 'response_ms' || item.outcome === 'contained')
          .map((item) => item[key]).filter((value) => Number.isFinite(value) && value >= 0);
        statistics[mode][key] = { count: values.length, meanMs: values.length ? values.reduce((a, b) => a + b, 0) / values.length : null };
      }
    }
    return { lines: records.length, rounds: metrics.length, statistics,
      containments: records.filter((item) => item?.event === 'endpoint.block_applied').length,
      releases: records.filter((item) => item?.event === 'endpoint.block_released').length,
      benchmark: records.find((item) => item?.event === 'siem.benchmark' && item.suite === 'clinic-security-v1'),
      ollamaTriages: metrics.filter((item) => item.mode === 'llm' && Number.isFinite(item.triage_ms)).map((item) => item.triage_ms).sort((a, b) => a - b) };
  }

  return { containmentMeans, interval, containmentVerified, historicalSummary };
});
