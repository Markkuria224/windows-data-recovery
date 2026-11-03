document.addEventListener('DOMContentLoaded', () => {
  const totalEvents = document.getElementById('total-events');
  const successfulLogins = document.getElementById('successful-logins');
  const failedLogins = document.getElementById('failed-logins');
  const suspiciousIps = document.getElementById('suspicious-ips');
  const liveIndicator = document.getElementById('live-mode-indicator');
  const startButton = document.getElementById('start-live-mode');
  const stopButton = document.getElementById('stop-live-mode');
  const alertsTableBody = document.getElementById('alerts-table-body');
  const windowsEventsBody = document.getElementById('windows-events-body');
  const windowsCollectionStatus = document.getElementById('windows-collection-status');
  const windowsRefreshButton = document.getElementById('refresh-windows-events');
  const windowsPollInterval = document.getElementById('windows-poll-interval');
  const csvImportForm = document.getElementById('csv-import-form');
  const csvImportStatus = document.getElementById('csv-import-status');
  const csvImportButton = document.getElementById('csv-import-submit');
  const navLinks = [...document.querySelectorAll('.nav [data-view-target]')];
  const views = [...document.querySelectorAll('[data-view]')];
  const viewIds = new Set(views.map((view) => view.id));

  let liveIntervalId = null;
  let windowsPollIntervalId = null;
  let windowsCollectionAvailable = false;

  const updateNavigation = () => {
    let activeViewId = window.location.hash.slice(1).toLowerCase();
    if (!viewIds.has(activeViewId)) {
      activeViewId = 'overview';
      window.history.replaceState(null, '', `${window.location.pathname}${window.location.search}#overview`);
    }

    views.forEach((view) => {
      view.hidden = view.id !== activeViewId;
    });
    navLinks.forEach((link) => {
      const isActive = link.dataset.viewTarget === activeViewId;
      link.classList.toggle('active', isActive);
      if (isActive) {
        link.setAttribute('aria-current', 'page');
      } else {
        link.removeAttribute('aria-current');
      }
    });
  };

  window.addEventListener('hashchange', updateNavigation);
  updateNavigation();

  const setLiveState = (isOn) => {
    if (!liveIndicator) return;
    liveIndicator.classList.toggle('on', isOn);
    liveIndicator.classList.toggle('off', !isOn);
    const liveDot = document.createElement('span');
    liveDot.className = 'live-dot';
    liveIndicator.replaceChildren(liveDot, document.createTextNode(isOn ? 'Live Mode: ON' : 'Live Mode: OFF'));

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
    alertsTableBody.replaceChildren();

    if (!alerts.length) {
      const row = document.createElement('tr');
      const cell = document.createElement('td');
      cell.colSpan = 5;
      cell.className = 'empty-state';
      cell.textContent = 'No alerts match the selected filters.';
      row.append(cell);
      alertsTableBody.append(row);
      return;
    }

    alerts.forEach((alert) => {
      const history = Array.isArray(alert.history) ? alert.history : [];
      const notes = Array.isArray(alert.notes) ? alert.notes : [];
      const alertRow = document.createElement('tr');
      alertRow.className = 'alert-row';
      const timestampCell = document.createElement('td');
      timestampCell.textContent = alert.timestamp || '';
      alertRow.append(timestampCell);

      const sourceCell = document.createElement('td');
      const sourceIp = document.createElement('div');
      sourceIp.className = 'cell-ip';
      sourceIp.textContent = alert.source_ip || 'unknown';
      const sourceHost = document.createElement('small');
      sourceHost.textContent = alert.source_host || 'unknown';
      sourceCell.append(sourceIp, sourceHost);
      alertRow.append(sourceCell);

      const severityCell = document.createElement('td');
      const severity = ['LOW', 'MEDIUM', 'HIGH'].includes(String(alert.severity).toUpperCase())
        ? String(alert.severity).toUpperCase()
        : 'LOW';
      const severityBadge = document.createElement('span');
      severityBadge.className = `severity severity-${severity.toLowerCase()}`;
      severityBadge.textContent = severity;
      severityCell.append(severityBadge);
      alertRow.append(severityCell);

      const reasonCell = document.createElement('td');
      const reason = document.createElement('div');
      reason.className = 'alert-reason';
      reason.textContent = alert.reason || '';
      const metadata = document.createElement('div');
      metadata.className = 'alert-meta';
      const eventType = document.createElement('span');
      eventType.textContent = alert.event_type || 'event';
      const updatedAt = document.createElement('span');
      updatedAt.textContent = alert.updated_at || alert.created_at || '';
      metadata.append(eventType, updatedAt);
      reasonCell.append(reason, metadata);
      alertRow.append(reasonCell);

      const statusCell = document.createElement('td');
      const statusSelect = document.createElement('select');
      statusSelect.className = 'status-select';
      statusSelect.dataset.alertId = Number.isSafeInteger(alert.id) ? String(alert.id) : '';
      const allowedStatuses = ['Open', 'Investigating', 'Resolved', 'False Positive'];
      const currentStatus = allowedStatuses.includes(alert.status) ? alert.status : 'Open';
      allowedStatuses.forEach((status) => {
        const option = document.createElement('option');
        option.value = status;
        option.textContent = status;
        option.selected = status === currentStatus;
        statusSelect.append(option);
      });
      statusCell.append(statusSelect);
      alertRow.append(statusCell);

      const activityRow = document.createElement('tr');
      activityRow.className = 'activity-row';
      const activityCell = document.createElement('td');
      activityCell.colSpan = 5;
      const activity = document.createElement('div');
      activity.className = 'alert-activity';

      const noteBox = document.createElement('div');
      noteBox.className = 'note-box';
      const noteHeading = document.createElement('h4');
      noteHeading.textContent = 'Investigation notes';
      const noteForm = document.createElement('form');
      noteForm.className = 'note-form';
      noteForm.dataset.alertId = statusSelect.dataset.alertId;
      const noteInput = document.createElement('textarea');
      noteInput.name = 'note';
      noteInput.placeholder = 'Add analyst note...';
      noteInput.rows = 2;
      const noteButton = document.createElement('button');
      noteButton.type = 'submit';
      noteButton.textContent = 'Add note';
      noteForm.append(noteInput, noteButton);
      noteBox.append(noteHeading, noteForm);

      const timelineBox = document.createElement('div');
      timelineBox.className = 'timeline-box';
      const timelineHeading = document.createElement('h4');
      timelineHeading.textContent = 'Activity timeline';
      const timeline = document.createElement('div');
      timeline.className = 'timeline';
      history.forEach((item) => {
        const timelineItem = document.createElement('div');
        timelineItem.className = 'timeline-item';
        const badge = document.createElement('span');
        badge.className = 'timeline-badge status';
        badge.textContent = item.new_status || '';
        const details = document.createElement('div');
        const title = document.createElement('strong');
        title.textContent = 'Status changed';
        const changedAt = document.createElement('small');
        changedAt.textContent = item.changed_at || '';
        details.append(title, changedAt);
        timelineItem.append(badge, details);
        timeline.append(timelineItem);
      });
      notes.forEach((note) => {
        const timelineItem = document.createElement('div');
        timelineItem.className = 'timeline-item note-item';
        const badge = document.createElement('span');
        badge.className = 'timeline-badge note';
        badge.textContent = 'Note';
        const details = document.createElement('div');
        const noteText = document.createElement('strong');
        noteText.textContent = note.note_text || '';
        const createdAt = document.createElement('small');
        createdAt.textContent = note.created_at || '';
        details.append(noteText, createdAt);
        timelineItem.append(badge, details);
        timeline.append(timelineItem);
      });
      if (!history.length && !notes.length) {
        const emptyItem = document.createElement('div');
        emptyItem.className = 'timeline-item empty-item';
        const badge = document.createElement('span');
        badge.className = 'timeline-badge neutral';
        badge.textContent = 'No activity';
        const details = document.createElement('div');
        const message = document.createElement('strong');
        message.textContent = 'No notes or status changes yet.';
        details.append(message);
        emptyItem.append(badge, details);
        timeline.append(emptyItem);
      }
      timelineBox.append(timelineHeading, timeline);
      activity.append(noteBox, timelineBox);
      activityCell.append(activity);
      activityRow.append(activityCell);
      alertsTableBody.append(alertRow, activityRow);
    });
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

  const buildWindowsFilterQuery = () => {
    const params = new URLSearchParams();
    const eventId = document.getElementById('windows-filter-event-id')?.value;
    const severity = document.getElementById('windows-filter-severity')?.value;
    const start = document.getElementById('windows-filter-start')?.value;
    const end = document.getElementById('windows-filter-end')?.value;
    if (eventId) params.set('event_id', eventId);
    if (severity) params.set('severity', severity);
    if (start) params.set('start', new Date(start).toISOString());
    if (end) params.set('end', new Date(end).toISOString());
    const query = params.toString();
    return query ? `?${query}` : '';
  };

  const renderWindowsEvents = (events) => {
    if (!windowsEventsBody) return;
    windowsEventsBody.replaceChildren();
    if (!events.length) {
      const row = document.createElement('tr');
      const cell = document.createElement('td');
      cell.colSpan = 8;
      cell.className = 'empty-state';
      cell.textContent = 'No Windows events match these filters.';
      row.append(cell);
      windowsEventsBody.append(row);
      return;
    }

    events.forEach((event) => {
      const row = document.createElement('tr');
      const values = [
        event.timestamp || '',
        event.event_id ?? '',
        event.severity || 'LOW',
        event.username || 'unknown',
        event.computer_name || 'unknown',
        event.source_ip || '—',
        event.logon_type || '—',
        event.description || 'No description available.',
      ];
      values.forEach((value, index) => {
        const cell = document.createElement('td');
        cell.textContent = String(value);
        if (index === 2) {
          const severity = ['LOW', 'MEDIUM', 'HIGH'].includes(String(value).toUpperCase())
            ? String(value).toUpperCase()
            : 'LOW';
          const badge = document.createElement('span');
          badge.className = `severity severity-${severity.toLowerCase()}`;
          badge.textContent = severity;
          cell.replaceChildren(badge);
        } else if (index === 7) {
          cell.className = 'windows-event-description';
        }
        row.append(cell);
      });
      windowsEventsBody.append(row);
    });
  };

  const setWindowsCollectionStatus = (state, message) => {
    if (!windowsCollectionStatus) return;
    windowsCollectionStatus.dataset.state = state || 'idle';
    windowsCollectionStatus.textContent = message || '';
  };

  const loadWindowsEvents = async (collect = false) => {
    if (collect && windowsRefreshButton) windowsRefreshButton.disabled = true;
    if (collect) setWindowsCollectionStatus('running', 'Reading the local Windows Security log...');

    try {
      if (collect) {
        const collectionResponse = await fetch('/api/windows-events/collect', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ lookback_hours: 24, max_events: 500 }),
        });
        const collection = await collectionResponse.json();
        if (!collectionResponse.ok) {
          setWindowsCollectionStatus(collection.status, collection.message || 'Windows event collection failed.');
        } else {
          setWindowsCollectionStatus(collection.status, collection.message);
        }
      }

      const response = await fetch(`/api/windows-events${buildWindowsFilterQuery()}`);
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Unable to load Windows events.');
      renderWindowsEvents(data.events || []);
      windowsCollectionAvailable = Boolean(data.collection.available);
      if (!collect || data.collection.status === 'unavailable') {
        setWindowsCollectionStatus(data.collection.status, data.collection.message);
      }
      if (windowsRefreshButton) windowsRefreshButton.disabled = !data.collection.available;
      configureWindowsPolling();
    } catch (error) {
      setWindowsCollectionStatus('error', error.message || 'Windows event collection failed.');
      if (windowsRefreshButton) windowsRefreshButton.disabled = false;
    } finally {
      if (collect && windowsRefreshButton && !windowsRefreshButton.disabled) {
        windowsRefreshButton.disabled = false;
      }
    }
  };

  const configureWindowsPolling = () => {
    if (windowsPollIntervalId) {
      clearInterval(windowsPollIntervalId);
      windowsPollIntervalId = null;
    }
    const minutes = Number(windowsPollInterval?.value || 0);
    const permissionDenied = windowsCollectionStatus?.dataset.state === 'permission_denied';
    if (windowsCollectionAvailable && !permissionDenied && minutes > 0) {
      windowsPollIntervalId = setInterval(() => loadWindowsEvents(true), minutes * 60 * 1000);
    }
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
      const chip = document.createElement('span');
      chip.className = 'filter-chip empty';
      chip.textContent = 'No filters active';
      summary.replaceChildren(chip);
      return;
    }

    summary.classList.remove('hidden');
    summary.replaceChildren(...chips.map((text) => {
      const chip = document.createElement('span');
      chip.className = 'filter-chip';
      chip.textContent = text;
      return chip;
    }));
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

  windowsRefreshButton?.addEventListener('click', () => loadWindowsEvents(true));
  windowsPollInterval?.addEventListener('change', configureWindowsPolling);
  ['windows-filter-event-id', 'windows-filter-severity', 'windows-filter-start', 'windows-filter-end'].forEach((id) => {
    document.getElementById(id)?.addEventListener('change', () => loadWindowsEvents(false));
  });

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

  csvImportForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (csvImportButton) csvImportButton.disabled = true;
    if (csvImportStatus) csvImportStatus.textContent = 'Validating and importing CSV logs...';

    try {
      const response = await fetch('/api/csv/import', {
        method: 'POST',
        body: new FormData(csvImportForm),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'CSV import failed.');
      if (csvImportStatus) {
        csvImportStatus.textContent = `Imported ${result.events_imported} events; ${result.duplicates} duplicates skipped; ${result.alerts_created} new alerts created.`;
      }
      csvImportForm.reset();
      await fetchDashboard();
    } catch (error) {
      if (csvImportStatus) csvImportStatus.textContent = error.message || 'CSV import failed.';
    } finally {
      if (csvImportButton) csvImportButton.disabled = false;
    }
  });

  fetchDashboard();
  loadWindowsEvents(false);
  configureWindowsPolling();
});
