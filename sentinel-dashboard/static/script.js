document.addEventListener('DOMContentLoaded', () => {
  const totalEvents = document.getElementById('total-events');
  const successfulLogins = document.getElementById('successful-logins');
  const failedLogins = document.getElementById('failed-logins');
  const suspiciousIps = document.getElementById('suspicious-ips');
  const liveIndicator = document.getElementById('live-mode-indicator');
  const startButton = document.getElementById('start-live-mode');
  const stopButton = document.getElementById('stop-live-mode');
  const alertsTableBody = document.getElementById('alerts-table-body');

  let liveIntervalId = null;

  const setLiveState = (isOn) => {
    if (!liveIndicator) return;
    liveIndicator.classList.toggle('on', isOn);
    liveIndicator.classList.toggle('off', !isOn);
    liveIndicator.innerHTML = `<span class="live-dot"></span>${isOn ? 'Live Mode: ON' : 'Live Mode: OFF'}`;

    if (startButton) {
      startButton.classList.toggle('hidden', isOn);
    }

    if (stopButton) {
      stopButton.classList.toggle('hidden', !isOn);
    }
  };

  const updateStatusCards = (summary) => {
    if (totalEvents) totalEvents.textContent = summary.total_events ?? 0;
    if (successfulLogins) successfulLogins.textContent = summary.successful_logins ?? 0;
    if (failedLogins) failedLogins.textContent = summary.failed_logins ?? 0;
    if (suspiciousIps) suspiciousIps.textContent = summary.suspicious_ips ?? 0;
  };

  const updateCharts = (summary) => {
    const trend = document.getElementById('eventTrendChart');
    const severity = document.getElementById('severityChart');
    const trendDataset = Array.isArray(summary.trend) && summary.trend.length
      ? summary.trend
      : [
          { label: 'Mon', value: 0 },
          { label: 'Tue', value: 0 },
          { label: 'Wed', value: 0 },
          { label: 'Thu', value: 0 },
          { label: 'Fri', value: 0 },
          { label: 'Sat', value: 0 },
        ];

    const trendLabels = trendDataset.map((item) => item.label ?? '');
    const trendValues = trendDataset.map((item) => Number(item.value ?? 0));

    if (trend) {
      if (!window.eventTrendChart || !window.eventTrendChart.data) {
        window.eventTrendChart = new Chart(trend, {
          type: 'line',
          data: {
            labels: trendLabels,
            datasets: [{
              label: 'Events',
              data: trendValues,
              borderColor: '#67e8a5',
              backgroundColor: 'rgba(103, 232, 165, 0.2)',
              fill: true,
              tension: 0.35,
            }],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            layout: {
              padding: {
                top: 8,
                right: 12,
                bottom: 4,
                left: 8,
              },
            },
            plugins: {
              legend: { display: false },
            },
            scales: {
              x: {
                ticks: {
                  maxTicksLimit: 7,
                  padding: 6,
                },
                grid: {
                  drawBorder: false,
                },
              },
              y: {
                beginAtZero: true,
                suggestedMax: 10,
                ticks: {
                  maxTicksLimit: 5,
                  padding: 6,
                },
                grid: {
                  drawBorder: false,
                },
              },
            },
          },
        });
      } else {
        window.eventTrendChart.data.labels = trendLabels;
        window.eventTrendChart.data.datasets[0].data = trendValues;
        window.eventTrendChart.update();
      }
    }

    const severityValues = [
      summary.severity_distribution?.LOW ?? 0,
      summary.severity_distribution?.MEDIUM ?? 0,
      summary.severity_distribution?.HIGH ?? 0,
    ];

    if (severity) {
      if (!window.severityChart || !window.severityChart.data) {
        window.severityChart = new Chart(severity, {
          type: 'doughnut',
          data: {
            labels: ['Low', 'Medium', 'High'],
            datasets: [{
              data: severityValues,
              backgroundColor: ['#5dd8ff', '#fbbf24', '#f87171'],
              borderWidth: 0,
            }],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '62%',
            layout: {
              padding: {
                top: 8,
                right: 8,
                bottom: 8,
                left: 8,
              },
            },
            plugins: {
              legend: {
                position: 'bottom',
              },
            },
          },
        });
      } else {
        window.severityChart.data.datasets[0].data = severityValues;
        window.severityChart.update();
      }
    }
  };

  const renderAlertTable = (alerts) => {
    if (!alertsTableBody) return;

    if (!alerts.length) {
      alertsTableBody.innerHTML = '<tr><td colspan="5" class="empty-state">No alerts match the selected filters.</td></tr>';
      return;
    }

    alertsTableBody.innerHTML = alerts.map((alert) => {
      const history = Array.isArray(alert.history) ? alert.history : [];
      const notes = Array.isArray(alert.notes) ? alert.notes : [];
      const timelineHtml = history.length || notes.length
        ? [
            ...history.map((item) => `
              <div class="timeline-item">
                <span class="timeline-badge status">${item.new_status}</span>
                <div>
                  <strong>Status changed</strong>
                  <small>${item.changed_at}</small>
                </div>
              </div>
            `),
            ...notes.map((note) => `
              <div class="timeline-item note-item">
                <span class="timeline-badge note">Note</span>
                <div>
                  <strong>${note.note_text}</strong>
                  <small>${note.created_at}</small>
                </div>
              </div>
            `),
          ].join('')
        : `
          <div class="timeline-item empty-item">
            <span class="timeline-badge neutral">No activity</span>
            <div>
              <strong>No notes or status changes yet.</strong>
            </div>
          </div>
        `;

      return `
        <tr class="alert-row">
          <td>${alert.timestamp}</td>
          <td>
            <div class="cell-ip">${alert.source_ip}</div>
            <small>${alert.source_host || 'unknown'}</small>
          </td>
          <td>
            <span class="severity severity-${String(alert.severity || 'LOW').toLowerCase()}">${alert.severity || 'LOW'}</span>
          </td>
          <td>
            <div class="alert-reason">${alert.reason}</div>
            <div class="alert-meta">
              <span>${alert.event_type || 'event'}</span>
              <span>${alert.updated_at || alert.created_at}</span>
            </div>
          </td>
          <td>
            <select class="status-select" data-alert-id="${alert.id}">
              <option value="Open" ${alert.status === 'Open' ? 'selected' : ''}>Open</option>
              <option value="Investigating" ${alert.status === 'Investigating' ? 'selected' : ''}>Investigating</option>
              <option value="Resolved" ${alert.status === 'Resolved' ? 'selected' : ''}>Resolved</option>
              <option value="False Positive" ${alert.status === 'False Positive' ? 'selected' : ''}>False Positive</option>
            </select>
          </td>
        </tr>
        <tr class="activity-row">
          <td colspan="5">
            <div class="alert-activity">
              <div class="note-box">
                <h4>Investigation notes</h4>
                <form class="note-form" data-alert-id="${alert.id}">
                  <textarea name="note" placeholder="Add analyst note..." rows="2"></textarea>
                  <button type="submit">Add note</button>
                </form>
              </div>

              <div class="timeline-box">
                <h4>Activity timeline</h4>
                <div class="timeline">
                  ${timelineHtml}
                </div>
              </div>
            </div>
          </td>
        </tr>
      `;
    }).join('');
  };

  const buildFilterQuery = () => {
    const params = new URLSearchParams();

    document.querySelectorAll('input[name="severity-filter"]:checked').forEach((checkbox) => {
      params.append('severity', checkbox.value);
    });

    document.querySelectorAll('input[name="status-filter"]:checked').forEach((checkbox) => {
      params.append('status', checkbox.value);
    });

    const sourceIp = document.getElementById('filter-source-ip')?.value.trim();
    const dateFrom = document.getElementById('filter-date-from')?.value;
    const dateTo = document.getElementById('filter-date-to')?.value;

    if (sourceIp) {
      params.set('source_ip', sourceIp);
    }

    if (dateFrom) {
      params.set('date_from', dateFrom);
    }

    if (dateTo) {
      params.set('date_to', dateTo);
    }

    const queryString = params.toString();
    return queryString ? `?${queryString}` : '';
  };

  const renderActiveFilterSummary = () => {
    const summary = document.getElementById('active-filter-summary');
    if (!summary) return;

    const selectedSeverities = [...document.querySelectorAll('input[name="severity-filter"]:checked')].map((checkbox) => checkbox.value);
    const selectedStatuses = [...document.querySelectorAll('input[name="status-filter"]:checked')].map((checkbox) => checkbox.value);
    const sourceIp = document.getElementById('filter-source-ip')?.value.trim();
    const dateFrom = document.getElementById('filter-date-from')?.value;
    const dateTo = document.getElementById('filter-date-to')?.value;

    const chips = [];

    if (selectedSeverities.length) {
      chips.push(`Severity: ${selectedSeverities.join(', ')}`);
    }

    if (selectedStatuses.length) {
      chips.push(`Status: ${selectedStatuses.join(', ')}`);
    }

    if (sourceIp) {
      chips.push(`Source IP: ${sourceIp}`);
    }

    if (dateFrom || dateTo) {
      chips.push(`Date: ${dateFrom || 'Any'} → ${dateTo || 'Any'}`);
    }

    if (!chips.length) {
      summary.classList.remove('hidden');
      summary.innerHTML = '<span class="filter-chip empty">No filters active</span>';
      return;
    }

    summary.classList.remove('hidden');
    summary.innerHTML = chips.map((chip) => `<span class="filter-chip">${chip}</span>`).join('');
  };

  const fetchDashboard = async () => {
    try {
      const query = buildFilterQuery();
      const response = await fetch(`/api/dashboard${query}`);
      if (!response.ok) {
        throw new Error('Unable to load dashboard summary.');
      }
      const data = await response.json();
      updateStatusCards(data);
      updateCharts(data);
      renderAlertTable(data.alerts || []);
      renderActiveFilterSummary();
      setLiveState(Boolean(data.live_mode));
      return data;
    } catch (error) {
      console.error(error);
    }
  };

  const startLiveMode = async () => {
    try {
      const response = await fetch('/api/live/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'start' }),
      });

      if (!response.ok) {
        throw new Error('Unable to start live mode.');
      }

      setLiveState(true);
      if (liveIntervalId) {
        clearInterval(liveIntervalId);
      }
      liveIntervalId = setInterval(async () => {
        const response = await fetch('/api/live/simulate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ action: 'tick' }),
        });

        if (response.ok) {
          const data = await response.json();
          updateStatusCards(data);
          updateCharts(data);
          renderAlertTable(data.alerts || []);
          setLiveState(Boolean(data.live_mode));
        }
      }, 40000);
    } catch (error) {
      console.error(error);
      alert(error.message);
    }
  };

  const stopLiveMode = async () => {
    try {
      const response = await fetch('/api/live/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'stop' }),
      });

      if (!response.ok) {
        throw new Error('Unable to stop live mode.');
      }

      if (liveIntervalId) {
        clearInterval(liveIntervalId);
        liveIntervalId = null;
      }
      setLiveState(false);
      await fetchDashboard();
    } catch (error) {
      console.error(error);
      alert(error.message);
    }
  };

  const applyFilters = async () => {
    await fetchDashboard();
  };

  if (startButton) {
    startButton.addEventListener('click', startLiveMode);
  }

  if (stopButton) {
    stopButton.addEventListener('click', stopLiveMode);
  }

  document.querySelectorAll('input[name="severity-filter"]').forEach((checkbox) => {
      checkbox.addEventListener('change', () => {
        renderActiveFilterSummary();
        applyFilters();
      });
    });

    document.querySelectorAll('input[name="status-filter"]').forEach((checkbox) => {
      checkbox.addEventListener('change', () => {
        renderActiveFilterSummary();
        applyFilters();
      });
    });

    document.getElementById('filter-date-from')?.addEventListener('change', () => {
      renderActiveFilterSummary();
      applyFilters();
    });
    document.getElementById('filter-date-to')?.addEventListener('change', () => {
      renderActiveFilterSummary();
      applyFilters();
    });
    document.getElementById('filter-source-ip')?.addEventListener('input', () => {
      renderActiveFilterSummary();
      applyFilters();
    });
    document.getElementById('apply-filters')?.addEventListener('click', () => {
      renderActiveFilterSummary();
      applyFilters();
    });
  document.getElementById('clear-filters')?.addEventListener('click', () => {
    document.querySelectorAll('input[name="severity-filter"]').forEach((checkbox) => {
      checkbox.checked = false;
    });

    document.querySelectorAll('input[name="status-filter"]').forEach((checkbox) => {
      checkbox.checked = false;
    });

    const from = document.getElementById('filter-date-from');
    const to = document.getElementById('filter-date-to');
    const source = document.getElementById('filter-source-ip');

    if (from) from.value = '';
    if (to) to.value = '';
    if (source) source.value = '';

    renderActiveFilterSummary();
    fetchDashboard();
  });

  document.addEventListener('change', async (event) => {
    const target = event.target;
    if (!(target instanceof HTMLElement) || !target.matches('.status-select')) {
      return;
    }

    const alertId = target.dataset.alertId;
    const status = target.value;

    try {
      const response = await fetch(`/api/alerts/${alertId}/status`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status }),
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Failed to update alert status.');
      }

      await fetchDashboard();
    } catch (error) {
      alert(error.message);
    }
  });

  document.addEventListener('submit', async (event) => {
    const target = event.target;
    if (!(target instanceof HTMLElement) || !target.matches('.note-form')) {
      return;
    }

    event.preventDefault();
    const alertId = target.dataset.alertId;
    const textarea = target.querySelector('textarea');
    const note = textarea?.value.trim();

    if (!note) {
      alert('Please enter a note before saving.');
      return;
    }

    try {
      const response = await fetch(`/api/alerts/${alertId}/note`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ note }),
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Failed to add note.');
      }

      target.reset();
      await fetchDashboard();
    } catch (error) {
      alert(error.message);
    }
  });

  fetchDashboard();
});
