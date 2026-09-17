(function () {
  const elProvider = document.getElementById("provider");
  const elServerField = document.getElementById("server_field");
  const elAnthropicKeyField = document.getElementById("anthropic_key_field");
  const elAnthropicApiKey = document.getElementById("anthropic_api_key");
  const elOpenaiKeyField = document.getElementById("openai_key_field");
  const elOpenaiApiKey = document.getElementById("openai_api_key");
  const elFetchHelper = document.getElementById("fetch_helper");
  const elServer = document.getElementById("server");
  const elModelSelect = document.getElementById("model_select");
  const elBenchMode = document.getElementById("bench_mode");
  const elTimeout = document.getElementById("timeout");
  const elDelay = document.getElementById("delay");
  const elFetchModels = document.getElementById("fetch_models");
  const elStartRun = document.getElementById("start_run");
  const elRefreshEverything = document.getElementById("refresh_everything");
  const elRefreshRuns = document.getElementById("refresh_runs");
  const elClearAllRuns = document.getElementById("clear_all_runs");
  const elModelStatus = document.getElementById("model_status");
  const elRunsList = document.getElementById("runs_list");
  const elJobState = document.getElementById("job_state");
  const elJobActions = document.getElementById("job_actions");
  const elCancelJob = document.getElementById("cancel_job");
  const elActivityPanel = document.getElementById("activity_panel");
  const elJobLog = document.getElementById("job_log");
  const elTerminalLabel = document.getElementById("terminal_label");
  const elResultTitle = document.getElementById("result_title");
  const elResultSubtitle = document.getElementById("result_subtitle");
  const elResultPlaceholder = document.getElementById("result_placeholder");
  const elResultContent = document.getElementById("result_content");
  const elResultMetrics = document.getElementById("result_metrics");
  const elResultKpis = document.getElementById("result_kpis");
  const elVerdictBadge = document.getElementById("verdict_badge");
  const elAttentionList = document.getElementById("attention_list");
  const elDownloadPdfBtn = document.getElementById("download_pdf_btn");
  const elDownloadXlsxBtn = document.getElementById("download_xlsx_btn");
  const elTechnicalGrid = document.getElementById("technical_grid");
  const elObservationsBlock = document.getElementById("observations_block");
  const elObservationsList = document.getElementById("observations_list");

  let runs = [];
  let jobs = [];
  let activeRunId = null;
  let activeJobId = null;
  let modelCache = [];       // [{id, context_length?}, ...]
  let lastRunningJobId = null;

  // ── Helpers ──

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text) e.textContent = text;
    return e;
  }

  function friendlyTime(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;

    const now = new Date();
    const diff = now.getTime() - d.getTime();
    if (diff < 60000) return "just now";
    if (diff < 3600000) return Math.floor(diff / 60000) + "m ago";
    if (diff < 86400000) return Math.floor(diff / 3600000) + "h ago";

    return d.toLocaleString("en-US", {
      month: "short",
      day: "numeric",
      hour: "numeric",
      minute: "2-digit",
    });
  }

  function friendlyDuration(startIso, endIso) {
    if (!startIso || !endIso) return null;
    const ms = new Date(endIso).getTime() - new Date(startIso).getTime();
    if (Number.isNaN(ms) || ms < 0) return null;
    if (ms < 60000) return Math.round(ms / 1000) + "s";
    var totalMin = Math.floor(ms / 60000);
    if (totalMin >= 60) {
      // Roll into hours so long runs read "23h 32m", not "1412m 47s".
      return Math.floor(totalMin / 60) + "h " + (totalMin % 60) + "m";
    }
    var s = Math.round((ms % 60000) / 1000);
    return totalMin + "m " + s + "s";
  }

  function pct(n) { return typeof n === "number" ? n.toFixed(1) + "%" : "—"; }

  function shortFile(name) {
    if (!name) return "";
    // Truncate long filenames but keep extension
    if (name.length > 45) return name.slice(0, 38) + "…" + name.slice(name.lastIndexOf("."));
    return name;
  }

  async function fetchJson(url, options) {
    const response = await fetch(url, options);
    const data = await response.json();
    if (!response.ok) {
      throw new Error((data && data.detail) || "Request failed");
    }
    return data;
  }

  function setStatus(message, kind) {
    elModelStatus.className = "status-line" + (kind ? " " + kind : "");
    elModelStatus.textContent = message;
  }

  function setSelectOptions(selectEl, values, placeholder, selectedValues) {
    clear(selectEl);
    if (!values.length) {
      var option = document.createElement("option");
      option.textContent = placeholder;
      selectEl.appendChild(option);
      selectEl.disabled = true;
      return;
    }

    for (var i = 0; i < values.length; i++) {
      var option = document.createElement("option");
      option.value = values[i];
      option.textContent = values[i];
      if (Array.isArray(selectedValues) && selectedValues.includes(values[i])) {
        option.selected = true;
      }
      selectEl.appendChild(option);
    }
    selectEl.disabled = false;
  }

  // ── Bench mode presets ──

  var BENCH_PRESETS = {
    smoke:    { mode: "sample", sample_size: 5,  difficulty: null, test_set: null,
                include_benign: true },
    standard: { mode: "sample", sample_size: 120, difficulty: null, test_set: null,
                include_benign: true },
    full:     { mode: "all",    sample_size: null, difficulty: null, test_set: null,
                include_benign: true },
  };

  // ── Provider ──

  function currentProvider() {
    return (elProvider && elProvider.value) || "lmstudio";
  }

  function syncProvider() {
    var provider = currentProvider();
    var isAnthropic = provider === "anthropic";
    var isOpenAI = provider === "openai";
    var isCloud = isAnthropic || isOpenAI;
    if (elServerField) elServerField.classList.toggle("hidden", isCloud);
    if (elAnthropicKeyField) elAnthropicKeyField.classList.toggle("hidden", !isAnthropic);
    if (elOpenaiKeyField) elOpenaiKeyField.classList.toggle("hidden", !isOpenAI);
    if (elFetchHelper) {
      elFetchHelper.textContent = isAnthropic ? "From Anthropic"
        : isOpenAI ? "From OpenAI"
        : "From the model server";
    }
    try { localStorage.setItem("forcast.provider", provider); } catch (e) {}
    resetModelsForProviderChange();
  }

  function resetModelsForProviderChange() {
    modelCache = [];
    setSelectOptions(elModelSelect, [], "Fetch models first");
    setStatus("Provider changed. Fetch models to refresh the list.");
  }

  // ── Models ──

  async function loadModels(silent) {
    var provider = currentProvider();
    var endpoint;
    var opts;   // POST body for key-bearing endpoints — keys never go in the URL

    if (provider === "anthropic") {
      var key = (elAnthropicApiKey && elAnthropicApiKey.value || "").trim();
      endpoint = "/api/anthropic/models";
      opts = { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ api_key: key || null }) };
    } else if (provider === "openai") {
      var oaiKey = (elOpenaiApiKey && elOpenaiApiKey.value || "").trim();
      endpoint = "/api/openai/models";
      opts = { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ api_key: oaiKey || null }) };
    } else {
      var server = (elServer.value || "").trim();
      if (!server) {
        setSelectOptions(elModelSelect, [], "Enter a server first");
        setStatus("Enter a server URL to load models.", "error");
        return;
      }
      endpoint = "/api/server/models?server=" + encodeURIComponent(server);
    }

    var priorPrimary = elModelSelect.value;
    elFetchModels.disabled = true;
    setStatus("Loading models…");

    try {
      var data = await fetchJson(endpoint, opts);
      modelCache = Array.isArray(data.models) ? data.models : [];
      var ids = modelCache.map(function(m) { return typeof m === "string" ? m : m.id; });

      setSelectOptions(elModelSelect, ids, "No models returned");

      if (ids.length) {
        if (priorPrimary && ids.includes(priorPrimary)) {
          elModelSelect.value = priorPrimary;
        } else {
          elModelSelect.selectedIndex = 0;
        }
        var sourceTag = (data.source === "fallback") ? " (curated list — enter a key + refetch for live)" : "";
        setStatus(ids.length + " models ready" + sourceTag + ".", "good");
      } else {
        setStatus("No models were returned.", "error");
      }
    } catch (error) {
      setSelectOptions(elModelSelect, [], "Connection failed");
      setStatus(error.message || String(error), "error");
    } finally {
      elFetchModels.disabled = false;
    }
  }

  // ── Summary sentence (richer) ──

  function summarySentence(run) {
    var summary = run && run.summary ? run.summary : {};
    var parts = [];

    if (typeof summary.processed === "number") {
      var total = typeof summary.total_files === "number" ? summary.total_files : summary.processed;
      if (total > summary.processed) {
        parts.push(summary.processed + " of " + total + " files processed");
      } else {
        parts.push(summary.processed + " files processed");
      }
    }
    if (typeof summary.malicious === "number" && typeof summary.benign === "number") {
      parts.push(summary.malicious + " malicious, " + summary.benign + " benign");
    } else if (typeof summary.malicious === "number" && summary.malicious > 0) {
      parts.push(summary.malicious + " flagged as malicious");
    }
    if (typeof summary.context_exceeded === "number" && summary.context_exceeded > 0) {
      parts.push(summary.context_exceeded + " skipped (context too large)");
    }
    if (typeof summary.error === "number" && summary.error > 0) {
      parts.push(summary.error + " failed with errors");
    }

    if (!parts.length) {
      return "Run completed. Select it to see details.";
    }
    return parts.join(" · ") + ".";
  }

  // ── Detailed summary for result panel ──

  function detailedSummary(run) {
    var summary = run && run.summary ? run.summary : {};
    var lines = [];

    // Opening line
    var total = typeof summary.total_files === "number" ? summary.total_files : summary.processed;
    if (typeof summary.processed === "number") {
      if (typeof total === "number" && total > summary.processed) {
        lines.push(summary.processed + " of " + total + " files were successfully processed.");
      } else {
        lines.push(summary.processed + " files processed.");
      }
    }

    // Classification breakdown
    if (typeof summary.malicious === "number" && typeof summary.benign === "number") {
      lines.push(summary.malicious + " classified as malicious, " + summary.benign + " as benign.");
    }

    // Quality line
    var qualParts = [];
    if (typeof summary.avg_alignment === "number") {
      qualParts.push(summary.avg_alignment.toFixed(1) + "% average alignment");
    }
    if (typeof summary.avg_hallucination_rate === "number") {
      qualParts.push((summary.avg_hallucination_rate * 100).toFixed(1) + "% hallucination rate");
    }
    if (qualParts.length) lines.push(qualParts.join(", ") + ".");

    // Problems line
    var problems = [];
    if (typeof summary.context_exceeded === "number" && summary.context_exceeded > 0) {
      problems.push(summary.context_exceeded + " file" + (summary.context_exceeded > 1 ? "s" : "") + " skipped because they exceeded the context window");
    }
    if (typeof summary.error === "number" && summary.error > 0) {
      problems.push(summary.error + " file" + (summary.error > 1 ? "s" : "") + " failed with errors");
    }
    if (problems.length) lines.push(problems.join("; ") + ".");

    // Grade distribution
    var gd = summary.grade_dist;
    if (gd && typeof gd === "object") {
      var gradeParts = [];
      ["A", "B", "C", "D"].forEach(function(g) {
        if (typeof gd[g] === "number" && gd[g] > 0) gradeParts.push(gd[g] + " " + g);
      });
      if (gradeParts.length) lines.push("Grades: " + gradeParts.join(", ") + ".");
    }

    if (!lines.length) return "Run completed.";
    return lines.join(" ");
  }

  // ── Metrics (expanded) ──

  // ── Verdict + primary KPIs ──

  var VERDICT_LABELS = {
    pass:    { label: "PASS",    sub: "Suitable for screening" },
    caution: { label: "CAUTION", sub: "Useful only with human review" },
    fail:    { label: "FAIL",    sub: "Not for production forensics" },
  };

  function renderVerdictBadge(summary) {
    if (!elVerdictBadge) return;
    var verdict = summary && summary.verdict;
    elVerdictBadge.classList.remove(
      "verdict-pass", "verdict-caution", "verdict-fail", "verdict-insufficient"
    );
    if (!verdict || typeof verdict !== "object") {
      elVerdictBadge.classList.add("hidden");
      elVerdictBadge.textContent = "";
      elVerdictBadge.title = "";
      return;
    }

    var tier = verdict.tier || "pass";
    var insufficient = !!verdict.insufficient;
    elVerdictBadge.classList.add(insufficient ? "verdict-insufficient" : ("verdict-" + tier));

    var label, sub;
    if (insufficient) {
      label = "NEEDS MORE DATA";
      sub = verdict.headline_sub || "No malicious ground truth available";
    } else {
      var meta = VERDICT_LABELS[tier] || { label: tier.toUpperCase(), sub: "" };
      label = meta.label;
      sub = meta.sub;
    }
    elVerdictBadge.textContent = label;

    // The detailed reasons live in the KPI cards below; keep the sub + reasons
    // as a hover tooltip so the badge stays compact without losing context.
    var reasons = Array.isArray(verdict.reasons) ? verdict.reasons : [];
    var tip = sub || "";
    if (reasons.length) tip += (tip ? "\n" : "") + reasons.join("\n");
    elVerdictBadge.title = tip;
    elVerdictBadge.classList.remove("hidden");
  }

  function primaryKpiEntries(summary) {
    /* Returns [{value, label, tier}] for the 3 KPIs that drive the verdict.
       Tier is one of "good"|"warn"|"bad"|"neutral" — used for color hint
       on the metric value. Mirrors config.VERDICT_THRESHOLDS server-side
       so the UI tier matches the verdict driver classification. */
    var driverTier = function(value, passBound, failBound, higherBetter) {
      if (value === null || value === undefined) return "neutral";
      if (higherBetter) {
        if (value >= passBound) return "good";
        if (value < failBound) return "bad";
      } else {
        if (value <= passBound) return "good";
        if (value > failBound) return "bad";
      }
      return "warn";
    };

    var entries = [];
    var hasBenign = summary && summary.has_benign_samples;

    var recall = summary && (summary.recall_pct);
    var fp = summary && (summary.fp_rate_pct);
    var hall = summary && summary.avg_hallucination_rate;
    var hallPct = (typeof hall === "number") ? hall * 100 : null;

    var tp = (summary && typeof summary.true_positives === "number") ? summary.true_positives : null;
    var tnCount = (summary && typeof summary.true_negatives === "number") ? summary.true_negatives : null;
    var fpCount = (summary && typeof summary.false_positives === "number") ? summary.false_positives : null;
    var totalMal = (summary && typeof summary.total_malicious_in_scope === "number") ? summary.total_malicious_in_scope : null;
    var totalBenign = (typeof fpCount === "number" && typeof tnCount === "number") ? (fpCount + tnCount) : null;

    var recallSub = (tp !== null && totalMal !== null && totalMal > 0)
      ? (tp + "/" + totalMal + " attacks caught")
      : "";
    var fpSub = "";
    if (totalBenign !== null && totalBenign > 0) {
      fpSub = fpCount + "/" + totalBenign + " benign mislabeled";
    }

    entries.push({
      value: (recall === null || recall === undefined) ? "—" : recall.toFixed(1) + "%",
      label: "Detection rate",
      sub: recallSub,
      tier: driverTier(recall, 90, 60, true),
    });
    entries.push({
      value: (fp === null || fp === undefined)
        ? (hasBenign ? "—" : "n/a")
        : fp.toFixed(1) + "%",
      label: hasBenign ? "False-positive rate" : "FP (no benign data)",
      sub: fpSub,
      tier: hasBenign ? driverTier(fp, 10, 50, false) : "neutral",
    });
    var hallFabricated = (summary && typeof summary.total_hallucinated_fields === "number")
      ? summary.total_hallucinated_fields : null;
    var hallClaimed = (summary && typeof summary.total_claimed_fields === "number")
      ? summary.total_claimed_fields : null;
    var hallSub = "";
    if (hallFabricated !== null && hallClaimed !== null && hallClaimed > 0) {
      hallSub = hallFabricated + "/" + hallClaimed + " fields fabricated";
    }

    entries.push({
      value: (hallPct === null) ? "—" : hallPct.toFixed(1) + "%",
      label: "Hallucination",
      sub: hallSub,
      tier: driverTier(hallPct, 10, 40, false),
    });
    return entries;
  }

  function _formatStarted(iso) {
    if (!iso) return "";
    try {
      var d = new Date(iso);
      if (isNaN(d.getTime())) return iso;
      return d.toLocaleString(undefined, {
        month: "long", day: "numeric", year: "numeric",
        hour: "numeric", minute: "2-digit",
      });
    } catch (e) { return iso; }
  }

  function _formatNumber(n) {
    if (typeof n !== "number" || !isFinite(n)) return null;
    return n.toLocaleString();
  }

  function _modeLabel(mode, size) {
    if (!mode) return null;
    var name = mode.charAt(0).toUpperCase() + mode.slice(1);
    if (mode === "sample" && typeof size === "number" && size > 0) {
      return name + " · " + size + " files";
    }
    return name;
  }

  /**
   * Render the Technical Details expander as a grouped key-value list.
   * Three groups (Run / Scope / Inference) cover identity, what the model
   * saw, and how generation was tuned. Empty / always-true fields are
   * dropped to keep the eye on what actually distinguishes one run from
   * another.
   */
  function renderTechnicalDetails(run) {
    if (!elTechnicalGrid) return;
    clear(elTechnicalGrid);
    if (!run) return;

    var contract = (run.benchmark_contract && run.benchmark_contract.effective_config) || {};
    var temperature = contract.temperature;
    var maxEvents = run.max_events != null ? run.max_events : contract.max_events;

    var groups = [
      {
        label: "Run",
        rows: [
          ["Model", run.model],
          ["Run ID", run.run_id, "is-mono"],
          ["Server", run.server],
          ["Started", _formatStarted(run.started_at)],
          ["Duration", friendlyDuration(run.started_at, run.finished_at)],
        ],
      },
      {
        label: "Scope",
        rows: [
          ["Mode", _modeLabel(run.mode, run.sample_size)],
          ["Input format", (run.input_format || "").toUpperCase()],
          run.input_format === "csv" ? ["CSV folder", run.csv_dir] : null,
          ["Max events / file", _formatNumber(maxEvents)],
          ["Difficulty filter", run.difficulty_filter],
          ["Test set filter", run.test_set_filter],
        ],
      },
      {
        label: "Inference",
        rows: [
          ["Context window", _formatNumber(run.context_window)],
          ["Max output tokens", _formatNumber(run.max_output_tokens)],
          ["Timeout", typeof run.timeout_s === "number" ? run.timeout_s + " s" : null],
          ["Delay", typeof run.delay_s === "number" ? run.delay_s + " s" : null],
          ["Temperature",
            (typeof temperature === "number") ? String(temperature) : null],
        ],
      },
    ];

    groups.forEach(function(g) {
      var rows = g.rows.filter(function(row) {
        if (!row) return false;
        var v = row[1];
        return v !== undefined && v !== null && v !== "";
      });
      if (!rows.length) return;
      var section = el("div", "details-group");
      section.appendChild(el("div", "details-group-label", g.label));
      var dl = el("dl", "details-kv");
      rows.forEach(function(row) {
        dl.appendChild(el("dt", null, row[0]));
        var ddClass = "details-kv-value" + (row[2] ? " " + row[2] : "");
        dl.appendChild(el("dd", ddClass, String(row[1])));
      });
      section.appendChild(dl);
      elTechnicalGrid.appendChild(section);
    });
  }

  /**
   * Render the More Details expander as a grouped key-value list.
   *
   * Replaces the prior 9-tile flat grid. Tiles are reserved for headlines
   * (KPIs above); details work better as a compact list grouped by question:
   * what the corpus was (Corpus), how the model classified (Accuracy),
   * and how the responses scored (Quality).
   */
  function renderMoreDetails(run) {
    if (!elResultMetrics) return;
    clear(elResultMetrics);
    var s = (run && run.summary) || {};
    var recs = Array.isArray(run && run.recommendations) ? run.recommendations : [];

    // Misclassified count comes from per-file alerts (same source the
    // dropped Misclassified tile used).
    var miscount = 0;
    recs.forEach(function(r) {
      if (r && r.id === "file-alert" && r.data && r.data.misclassified) miscount++;
    });
    var processed = (typeof s.processed === "number") ? s.processed : 0;
    var totalFiles = (typeof s.total_files === "number") ? s.total_files : processed;

    var groups = [
      {
        label: "Corpus",
        rows: [
          ["Total files", String(totalFiles)],
          ["Processed", String(processed)],
          (typeof s.context_exceeded === "number" && s.context_exceeded > 0)
            ? ["Context skipped", String(s.context_exceeded)] : null,
          (typeof s.error === "number" && s.error > 0)
            ? ["Errors", String(s.error)] : null,
        ],
      },
      {
        label: "Accuracy",
        rows: [
          processed > 0
            ? ["Correct", (processed - miscount) + " of " + totalFiles] : null,
          processed > 0 ? ["Misclassified", String(miscount)] : null,
        ],
      },
      {
        label: "Quality",
        rows: [
          (typeof s.avg_score_20 === "number")
            ? ["Avg score", s.avg_score_20.toFixed(1) + " / 20",
               "Average per-file score out of 20 = Extraction 6 + Interpretation 6 + No-hallucination 4 + Reasoning 4. Measures how good the analysis was, not just whether the verdict was right."] : null,
          (typeof s.avg_alignment === "number")
            ? ["Evidence captured", s.avg_alignment.toFixed(1) + "%",
               "How much of the ground-truth forensic evidence (event IDs, processes, accounts, commands, network, registry) the model correctly reported, by fuzzy match. This is the Extraction part of the score."] : null,
        ],
      },
    ];

    groups.forEach(function(g) {
      var rows = g.rows.filter(Boolean);
      if (!rows.length) return;
      var section = el("div", "details-group");
      section.appendChild(el("div", "details-group-label", g.label));
      var dl = el("dl", "details-kv");
      rows.forEach(function(row) {
        var dt = el("dt", null, row[0]);
        if (row[2]) {  // optional hover help
          var hint = el("span", "hint");
          hint.setAttribute("data-hint", row[2]);
          dt.appendChild(document.createTextNode(" "));
          dt.appendChild(hint);
        }
        dl.appendChild(dt);
        var ddClass = "details-kv-value";
        if (row[0] === "Errors" || row[0] === "Context skipped" || row[0] === "Misclassified") {
          if (parseInt(row[1], 10) > 0) ddClass += " is-bad";
        }
        dl.appendChild(el("dd", ddClass, row[1]));
      });
      section.appendChild(dl);
      elResultMetrics.appendChild(section);
    });
  }

  function metricEntries(summary, recs) {
    var entries = [];
    if (typeof summary.processed === "number") {
      var total = typeof summary.total_files === "number" ? summary.total_files : null;
      var label = total && total > summary.processed ? "Processed (" + total + " total)" : "Processed";
      entries.push([String(summary.processed), label]);
    }
    if (typeof summary.malicious === "number") entries.push([String(summary.malicious), "Malicious"]);
    if (typeof summary.benign === "number") entries.push([String(summary.benign), "Benign"]);
    if (typeof summary.context_exceeded === "number" && summary.context_exceeded > 0) {
      entries.push([String(summary.context_exceeded), "Context skipped"]);
    }
    if (typeof summary.error === "number" && summary.error > 0) {
      entries.push([String(summary.error), "Errors"]);
    }

    // Correct / Misclassified — derived from per-file alerts so the denominator
    // includes errored files (1/2, not 1/1, when one file errored).
    var proc = typeof summary.processed === "number" ? summary.processed : 0;
    var miscount = 0;
    if (Array.isArray(recs)) {
      recs.forEach(function(r) {
        if (r && r.id === "file-alert" && r.data && r.data.misclassified) miscount++;
      });
    }
    if (proc > 0) {
      var correct = proc - miscount;
      var denom = typeof summary.total_files === "number" ? summary.total_files : proc;
      entries.push([correct + "/" + denom, "Correct"]);
      entries.push([String(miscount), "Misclassified"]);
    }

    if (typeof summary.avg_alignment === "number") entries.push([summary.avg_alignment.toFixed(1) + "%", "Alignment"]);
    if (typeof summary.avg_hallucination_rate === "number") {
      entries.push([(summary.avg_hallucination_rate * 100).toFixed(1) + "%", "Hallucination"]);
    }
    if (typeof summary.avg_score_20 === "number") {
      entries.push([summary.avg_score_20.toFixed(1) + "/20", "Avg score"]);
    }
    return entries;
  }

  // ── Recommendation rendering ──

  var SEVERITY_LABELS = {
    critical: "Critical",
    warning: "Warning",
    info: "Info",
  };

  var CATEGORY_LABELS = {
    per_file: "Per-file issue",
    configuration: "Configuration",
    quality: "Quality",
  };

  function recSeverityLabel(rec) {
    return SEVERITY_LABELS[rec.severity] || rec.severity || "Note";
  }

  function recCategoryLabel(rec) {
    return CATEGORY_LABELS[rec.category] || (rec.category || "note").replace(/_/g, " ");
  }

  /** Build an actionable suggestion string from rec.id + rec.data */
  function actionableTip(rec) {
    var data = rec.data || {};

    switch (rec.id) {
      case "cfg-context-exceeded": {
        var parts = [];
        if (typeof data.suggested_max_tokens === "number") {
          parts.push("These files exceed the model's context window. Raising the context length in your LLM server (e.g. LM Studio) — or capping output to ~" + data.suggested_max_tokens + " tokens there — would recover some.");
        }
        if (Array.isArray(data.gaps) && data.gaps.length) {
          var recoverable = data.gaps.filter(function(g) { return g.gap <= 500; });
          var large = data.gaps.filter(function(g) { return g.gap > 500; });
          if (recoverable.length) {
            parts.push(recoverable.length + " file" + (recoverable.length > 1 ? "s are" : " is") + " close to fitting — a small context limit increase would help.");
          }
          if (large.length) {
            parts.push(large.length + " file" + (large.length > 1 ? "s are" : " is") + " far too large for the current context window.");
          }
        }
        return parts.join(" ") || null;
      }

      case "cfg-near-miss":
        return "A small increase to Context limit would add safety margin.";

      case "cfg-slow-files":
        return "Response time was over 3x the average. Consider increasing Timeout if these files are important.";

      case "qual-high-hallucination": {
        var tip = "The model is inventing evidence not in the source data.";
        tip += " Try a larger model or verify results manually.";
        return tip;
      }

      case "qual-low-alignment":
        return "Consider a model with better instruction following.";

      case "qual-grade-d":
        return "Open the per-file CSV to inspect the failing extractions.";

      case "qual-all-malicious":
        return "The model may be biased toward positive detections. Switch Mode to Mixed to measure FP rate.";

      case "qual-all-benign":
        return "The model may be too conservative. Try with known-malicious samples to verify.";

      case "qual-low-reasoning":
        return "The model may be too small or the prompt may need adjustment.";

      // file-alert tip is intentionally null — the description already names the file
      // and the issue, so the arrow line would just repeat what's above.

      default:
        return null;
    }
  }

  /** Build the context-exceeded gap detail table */
  function buildGapDetail(gaps) {
    if (!Array.isArray(gaps) || !gaps.length) return null;

    var table = document.createElement("div");
    table.className = "rec-gap-table";

    gaps.forEach(function(g) {
      var row = el("div", "rec-gap-row");
      var name = el("span", "rec-gap-file", shortFile(g.file));
      name.title = g.file;
      var info = el("span", "rec-gap-info");
      if (g.gap <= 500) {
        info.textContent = "Over by " + g.gap + " tokens — recoverable";
        info.classList.add("recoverable");
      } else {
        info.textContent = g.estimated.toLocaleString() + " tokens (budget: " + g.budget.toLocaleString() + ")";
      }
      row.appendChild(name);
      row.appendChild(info);
      table.appendChild(row);
    });

    return table;
  }

  /** Build affected files as clickable pills */
  function buildAffectedFiles(files) {
    if (!Array.isArray(files) || !files.length) return null;
    var wrap = el("div", "rec-files");
    var label = el("span", "rec-files-label", "Affected: ");
    wrap.appendChild(label);
    files.forEach(function(f) {
      var pill = el("span", "rec-file-pill");
      pill.textContent = shortFile(f);
      pill.title = f;
      wrap.appendChild(pill);
    });
    return wrap;
  }

  /** Bin per-file alerts by symptom so 5 identical-shape cards become 1.
      Single-occurrence alerts pass through unchanged. */
  function groupRecommendations(recs) {
    var bins = { misclassified: [], hallucination: [], alignment: [] };
    var passthrough = [];

    recs.forEach(function(r) {
      if (!r || r.id !== "file-alert") { passthrough.push(r); return; }
      var data = r.data || {};
      if (data.misclassified) {
        bins.misclassified.push(r);
      } else if (typeof data.hallucination_pct === "number" || /hallucination/i.test(r.title || "")) {
        bins.hallucination.push(r);
      } else if (typeof data.alignment_pct === "number" || /alignment/i.test(r.title || "")) {
        bins.alignment.push(r);
      } else {
        passthrough.push(r);
      }
    });

    var grouped = [];
    function pushGroup(items, kind, label) {
      if (!items.length) return;
      if (items.length === 1) { grouped.push(items[0]); return; }
      var children = items.map(function(r) {
        var fname = (r.affected_files && r.affected_files[0]) || "";
        var d = r.data || {};
        var detail = "", context = [];
        if (d.misclassified) {
          detail = "expected " + (d.expected_label || "?");
          context = _misclassContext(d);
        } else if (typeof d.hallucination_pct === "number") {
          detail = "hallucination " + d.hallucination_pct + "%";
        } else if (typeof d.alignment_pct === "number") {
          detail = "alignment " + d.alignment_pct + "%";
        }
        return { filename: fname, detail: detail, context: context };
      });
      grouped.push({
        id: "file-alert-group-" + kind,
        category: "per_file",
        severity: "warning",
        title: items.length + " " + label,
        description: null,
        affected_files: items.map(function(r) {
          return (r.affected_files && r.affected_files[0]) || "";
        }).filter(Boolean),
        _children: children,
      });
    }
    pushGroup(bins.misclassified, "misclass", "misclassifications");
    pushGroup(bins.hallucination, "hall", "files with hallucinated evidence");
    pushGroup(bins.alignment, "align", "files with low alignment");

    // Give the "files failed to process" rec the same expandable per-file rows,
    // labelled by why each failed (timeout / too large / other).
    passthrough = passthrough.map(function(r) {
      if (!r || r.id !== "cfg-files-errored" || !r.data) return r;
      var d = r.data, ch = [];
      (d.timeouts || []).forEach(function(f) {
        ch.push({ filename: f, detail: "timed out",
          context: ["Ran past the " + (d.timeout_s || "") + "s timeout and was abandoned — counts as a missed detection. Raise the timeout to recover it."] });
      });
      (d.oversized || []).forEach(function(f) {
        ch.push({ filename: f, detail: "too large",
          context: ["Failed immediately — the file's events are likely too large for the model's context window. A larger-context model or trimming would be needed."] });
      });
      (d.other || []).forEach(function(f) {
        ch.push({ filename: f, detail: "failed",
          context: ["The request failed (connection error or other failure)."] });
      });
      var copy = {}; for (var k in r) copy[k] = r[k];
      copy._children = ch;
      return copy;
    });
    return grouped.concat(passthrough);
  }

  /** Build the expandable context lines for a misclassification finding. */
  function _misclassContext(d) {
    var lines = [];
    if (d.expected_label && d.got_label) {
      lines.push("Ground truth: " + d.expected_label + " — model said: " + d.got_label);
    }
    if (typeof d.score_20 === "number") lines.push("Score: " + d.score_20 + " / 20");
    if (typeof d.alignment_pct === "number") lines.push("Evidence alignment: " + d.alignment_pct + "%");
    if (d.explanation) lines.push("Model reasoning: " + d.explanation);
    return lines;
  }

  function buildRecommendation(rec) {
    var item = el("div", "attention-item");
    item.dataset.severity = rec.severity || "info";

    // Header row: severity badge only - category chip was redundant with the title
    var header = el("div", "rec-header");
    var badge = el("span", "rec-severity-badge rec-severity-" + (rec.severity || "info"), recSeverityLabel(rec));
    header.appendChild(badge);
    item.appendChild(header);

    // Title
    var title = el("div", "attention-title", rec.title || "Untitled");
    item.appendChild(title);

    // Description (skipped when null - grouped items use a child list instead)
    if (rec.description) {
      var copy = el("div", "attention-copy", rec.description);
      item.appendChild(copy);
    }

    // Grouped child list - per-file details for binned alerts. Rows with extra
    // context are clickable and expand to reveal it.
    if (Array.isArray(rec._children) && rec._children.length) {
      var listEl = el("ul", "rec-children");
      rec._children.forEach(function(c) {
        var li = el("li", "rec-children-item");
        var row = el("div", "rec-children-row");
        var hasCtx = Array.isArray(c.context) && c.context.length;
        if (hasCtx) {
          row.classList.add("rec-row-expandable");
          row.appendChild(el("span", "rec-children-chevron", "▸"));
        }
        row.appendChild(el("span", "rec-children-file", c.filename || "—"));
        if (c.detail) row.appendChild(el("span", "rec-children-detail", c.detail));
        li.appendChild(row);
        if (hasCtx) {
          var ctx = el("div", "rec-children-context hidden");
          c.context.forEach(function(line) {
            ctx.appendChild(el("div", "rec-context-line", line));
          });
          li.appendChild(ctx);
          row.addEventListener("click", function() {
            var nowHidden = ctx.classList.toggle("hidden");
            li.classList.toggle("expanded", !nowHidden);
          });
        }
        listEl.appendChild(li);
      });
      item.appendChild(listEl);
    }

    // Actionable tip - only render when it adds new info beyond the description
    var tip = actionableTip(rec);
    var descNorm = (rec.description || "").trim().toLowerCase();
    var tipNorm = (tip || "").trim().toLowerCase();
    if (tip && tipNorm !== descNorm) {
      var tipEl = el("div", "rec-action-tip");
      var tipIcon = el("span", "rec-tip-icon", "→");
      var tipText = el("span", null, tip);
      tipEl.appendChild(tipIcon);
      tipEl.appendChild(tipText);
      item.appendChild(tipEl);
    }

    // Gap detail for context-exceeded
    if (rec.id === "cfg-context-exceeded" && rec.data && rec.data.gaps) {
      var gapTable = buildGapDetail(rec.data.gaps);
      if (gapTable) item.appendChild(gapTable);
    }

    // Affected files - skip when grouped (children render the file list inline)
    // or when the title already names the only affected file.
    if (!Array.isArray(rec._children)) {
      var affected = Array.isArray(rec.affected_files) ? rec.affected_files : [];
      var titleLower = (rec.title || "").toLowerCase();
      var redundant = (
        affected.length === 1 &&
        titleLower.indexOf(String(affected[0]).toLowerCase()) !== -1
      );
      if (!redundant) {
        var filesEl = buildAffectedFiles(rec.affected_files);
        if (filesEl) item.appendChild(filesEl);
      }
    }

    return item;
  }

  // ── Output rows ──

  function outputRows(run) {
    var rows = [];

    if (run && run.outputs && typeof run.outputs === "object") {
      for (var key in run.outputs) {
        var path = run.outputs[key];
        if (typeof path !== "string" || !path) continue;
        rows.push([key.replace(/_/g, " "), path]);
      }
    }

    if (Array.isArray(run.models)) {
      run.models.forEach(function(modelRun) {
        if (!modelRun || typeof modelRun !== "object") return;
        if (typeof modelRun.html_report === "string") {
          rows.push([modelRun.model + " report", modelRun.html_report]);
        }
        if (typeof modelRun.csv_results === "string") {
          rows.push([modelRun.model + " csv", modelRun.csv_results]);
        }
      });
    }

    if (typeof run.comparison_report === "string") {
      rows.push(["comparison report", run.comparison_report]);
    }

    return rows;
  }

  function linkForOutput(path) {
    var fileName = String(path || "").split(/[\\/]/).pop() || path;
    var anchor = document.createElement("a");
    anchor.href = "/api/outputs/file?path=" + encodeURIComponent(fileName);
    anchor.target = "_blank";
    anchor.rel = "noreferrer";
    anchor.textContent = fileName;
    return anchor;
  }

  // ── Render result ──

  function renderResult(run) {
    if (!run) {
      elResultTitle.textContent = "Select a run";
      elResultSubtitle.textContent = "Choose a run from the sidebar to view its results.";
      if (elVerdictBadge) elVerdictBadge.classList.add("hidden");
      elResultPlaceholder.classList.remove("hidden");
      elResultContent.classList.add("hidden");
      // Hide download buttons — they're meaningless without a selected run.
      if (elDownloadPdfBtn) {
        elDownloadPdfBtn.classList.add("hidden");
        delete elDownloadPdfBtn.dataset.manifest;
      }
      if (elDownloadXlsxBtn) {
        elDownloadXlsxBtn.classList.add("hidden");
        delete elDownloadXlsxBtn.dataset.manifest;
      }
      return;
    }

    elResultTitle.textContent = run.model || (Array.isArray(run.models) ? "Comparison run" : run.run_id || "Selected run");

    // Subtitle with time + duration + server
    var subParts = [];
    subParts.push(friendlyTime(run.started_at));
    var dur = friendlyDuration(run.started_at, run.finished_at);
    if (dur) subParts.push("took " + dur);
    if (run.server) subParts.push("on " + run.server);
    elResultSubtitle.textContent = subParts.join(" · ");

    // Verdict badge (next to the model name)
    renderVerdictBadge(run.summary || {});

    // Primary KPIs (3 cards: Detection / FP / Hallucination)
    var TIER_COLOR = {
      good: "var(--good)",
      warn: "var(--warn)",
      bad: "var(--bad)",
      neutral: "var(--text-primary)",
    };
    if (elResultKpis) {
      clear(elResultKpis);
      primaryKpiEntries(run.summary || {}).forEach(function(k) {
        var metric = el("div", "metric");
        var valueEl = el("div", "metric-value", k.value);
        valueEl.style.color = TIER_COLOR[k.tier] || TIER_COLOR.neutral;
        metric.appendChild(valueEl);
        metric.appendChild(el("div", "metric-label", k.label));
        if (k.sub) {
          metric.appendChild(el("div", "metric-sub", k.sub));
        }
        elResultKpis.appendChild(metric);
      });
    }

    // Secondary metrics — grouped key-value list under "More details"
    renderMoreDetails(run);

    // Recommendations — bin per-file alerts by symptom before render.
    // Drop the run-level verdict rec: it's already shown (with its reasons) in
    // the verdict banner above the KPI cards, so repeating it under "Needs
    // attention" is redundant.
    var rawRecs = (Array.isArray(run.recommendations) ? run.recommendations : [])
      .filter(function(r) { return r && r.category !== "verdict"; });
    var recs = groupRecommendations(rawRecs);
    var attention = recs.filter(function(r) { return r.severity !== "info"; });
    var observations = recs.filter(function(r) { return r.severity === "info"; });

    clear(elAttentionList);
    if (attention.length) {
      // Sort: critical first, then warning
      attention.sort(function(a, b) {
        var order = { critical: 0, warning: 1 };
        return (order[a.severity] || 2) - (order[b.severity] || 2);
      });
      attention.slice(0, 10).forEach(function(rec) {
        elAttentionList.appendChild(buildRecommendation(rec));
      });
    } else {
      var empty = el("div", "placeholder", "No issues found — all results look clean.");
      elAttentionList.appendChild(empty);
    }

    clear(elObservationsList);
    if (observations.length) {
      elObservationsBlock.classList.remove("hidden");
      observations.slice(0, 6).forEach(function(rec) {
        elObservationsList.appendChild(buildRecommendation(rec));
      });
    } else {
      elObservationsBlock.classList.add("hidden");
    }

    // PDF + XLSX downloads — show whenever a run is selected. The XLSX is the
    // troubleshooting artifact: sheet 1 is the standard prompt, sheet 2 is the
    // per-file table with full LLM responses and parsed evidence.
    var manifestName = run && typeof run.manifest_path === "string" ? run.manifest_path : null;
    var hasCsv = !!(run && run.outputs && run.outputs.csv_results);
    if (elDownloadPdfBtn) {
      if (manifestName) {
        elDownloadPdfBtn.classList.remove("hidden");
        elDownloadPdfBtn.dataset.manifest = manifestName;
      } else {
        elDownloadPdfBtn.classList.add("hidden");
        delete elDownloadPdfBtn.dataset.manifest;
      }
    }
    if (elDownloadXlsxBtn) {
      if (manifestName && hasCsv) {
        elDownloadXlsxBtn.classList.remove("hidden");
        elDownloadXlsxBtn.dataset.manifest = manifestName;
      } else {
        elDownloadXlsxBtn.classList.add("hidden");
        delete elDownloadXlsxBtn.dataset.manifest;
      }
    }

    // Technical details — grouped key-value list, same pattern as More Details
    renderTechnicalDetails(run);

    elResultPlaceholder.classList.add("hidden");
    elResultContent.classList.remove("hidden");
  }

  // ── Run list ──

  function runLabel(run) {
    if (run.model) return run.model;
    if (Array.isArray(run.models) && run.models.length) {
      var models = run.models.map(function(e) { return typeof e === "object" ? e.model : e; }).filter(Boolean);
      return models.join(", ");
    }
    return run.run_id || "Unnamed run";
  }

  function renderRuns() {
    clear(elRunsList);

    if (!runs.length) {
      elRunsList.appendChild(el("div", "placeholder", "No runs yet. Start one from the panel above."));
      return;
    }

    runs.slice(0, 12).forEach(function(run) {
      var item = el("div", "run-item" + (run.run_id === activeRunId ? " active" : ""));
      item.addEventListener("click", function() { loadRun(run.run_id); });

      // Top row: optional COMPARE tag + model name (left), timestamp + delete (right)
      var row = el("div", "run-row");
      var left = el("div", "run-row-left");

      var isCompare = run.kind === "compare" || run.kind === "comparison";
      if (isCompare) {
        left.appendChild(el("span", "run-kind compare", "compare"));
      }
      left.appendChild(el("div", "run-title", runLabel(run)));
      row.appendChild(left);

      var rightGroup = el("div", "run-row-right");
      rightGroup.appendChild(el("div", "run-copy", friendlyTime(run.started_at)));

      var delBtn = el("button", "run-delete-btn");
      var delLabel = "Delete " + runLabel(run);
      delBtn.title = delLabel;
      delBtn.setAttribute("aria-label", delLabel);
      delBtn.innerHTML = '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" aria-hidden="true"><path d="M2.5 4.5h11M5.5 4.5V3a1 1 0 011-1h3a1 1 0 011 1v1.5M6.5 7v4.5M9.5 7v4.5M3.5 4.5l.5 8.5a1 1 0 001 1h6a1 1 0 001-1l.5-8.5"/></svg>';
      delBtn.addEventListener("click", function(e) {
        e.stopPropagation();
        deleteRun(run.run_id, runLabel(run));
      });
      rightGroup.appendChild(delBtn);
      row.appendChild(rightGroup);
      item.appendChild(row);

      // Verdict + driver line (inline ratios, color-coded tier badge)
      var summary = run.summary || {};
      item.appendChild(buildRunVerdictLine(summary));
      item.appendChild(buildRunScopeLine(summary));

      elRunsList.appendChild(item);
    });
  }

  function buildRunVerdictLine(summary) {
    var line = el("div", "run-verdict-line");
    var verdict = summary && summary.verdict;
    var hasBenign = summary && summary.has_benign_samples;

    if (verdict && typeof verdict === "object") {
      var tier = verdict.insufficient ? "insufficient"
                                      : (verdict.tier || "pass");
      var label = (tier === "insufficient") ? "INSUFFICIENT"
                                            : (tier.toUpperCase());
      line.appendChild(el("span", "run-verdict-badge run-verdict-" + tier, label));
    }

    var pieces = [];
    var tp = summary.true_positives, totalMal = summary.total_malicious_in_scope;
    if (typeof tp === "number" && typeof totalMal === "number" && totalMal > 0) {
      pieces.push(tp + "/" + totalMal + " caught");
    }
    var fp = summary.false_positives, fpRate = summary.fp_rate_pct;
    var totalBenign = (typeof fp === "number" && typeof summary.true_negatives === "number")
      ? (fp + summary.true_negatives) : null;
    if (hasBenign && totalBenign && totalBenign > 0) {
      pieces.push(fp + "/" + totalBenign + " mislabeled");
    }
    var hall = summary.avg_hallucination_rate;
    if (typeof hall === "number") {
      pieces.push((hall * 100).toFixed(1) + "% hall");
    }

    if (pieces.length) {
      line.appendChild(el("span", "run-verdict-stats", pieces.join(" · ")));
    }
    return line;
  }

  function buildRunScopeLine(summary) {
    var pieces = [];
    var processed = summary.processed;
    var total = (typeof summary.total_files === "number") ? summary.total_files : processed;
    if (typeof processed === "number") {
      if (typeof total === "number" && total !== processed) {
        pieces.push(processed + " of " + total + " files");
      } else {
        pieces.push(processed + (processed === 1 ? " file" : " files"));
      }
    }
    if (typeof summary.error === "number" && summary.error > 0) {
      pieces.push(summary.error + (summary.error === 1 ? " error" : " errors"));
    }
    if (typeof summary.context_exceeded === "number" && summary.context_exceeded > 0) {
      pieces.push(summary.context_exceeded + " skipped");
    }
    var line = el("div", "run-scope-line", pieces.join(" · ") || "—");
    return line;
  }

  async function loadRun(runId) {
    activeRunId = runId;
    renderRuns();
    try {
      var run = await fetchJson("/api/runs/" + encodeURIComponent(runId));
      renderResult(run);
    } catch (error) {
      renderResult(null);
      window.alert(error.message || String(error));
    }
  }

  async function deleteRun(runId, label) {
    if (!window.confirm("Delete \"" + label + "\" and all its output files?\n\nThis cannot be undone.")) {
      return;
    }
    try {
      await fetchJson("/api/runs/" + encodeURIComponent(runId), { method: "DELETE" });
      // If we were viewing this run, clear the result panel
      if (activeRunId === runId) {
        activeRunId = null;
        renderResult(null);
      }
      await refreshRuns();
    } catch (error) {
      window.alert("Failed to delete: " + (error.message || String(error)));
    }
  }

  async function deleteAllRuns() {
    if (!runs.length) return;
    if (!window.confirm("Delete all " + runs.length + " runs and their output files?\n\nThis cannot be undone.")) {
      return;
    }
    var failed = 0;
    for (var i = 0; i < runs.length; i++) {
      try {
        await fetchJson("/api/runs/" + encodeURIComponent(runs[i].run_id), { method: "DELETE" });
      } catch (_) {
        failed++;
      }
    }
    activeRunId = null;
    renderResult(null);
    await refreshRuns();
    if (failed > 0) {
      window.alert(failed + " run(s) could not be deleted.");
    }
  }

  // ── Job state ──

  function updateJobState(job, logText) {
    var isRunning = job && job.status === "running";

    elJobState.classList.add("hidden");
    elJobLog.classList.add("hidden");
    elJobActions.classList.add("hidden");
    elActivityPanel.classList.toggle("is-running", !!isRunning);

    if (!isRunning) {
      if (activeJobId && job && activeJobId === job.job_id) activeJobId = null;
      elTerminalLabel.textContent = "No benchmark running";
      return;
    }

    activeJobId = job.job_id;

    // Heartbeat: how long since the log file was last touched. Healthy runs
    // tick every few seconds; an unbounded number means the process is wedged.
    var heartbeatBits = [];
    var lastWrite = (typeof job.last_write_seconds_ago === "number")
      ? job.last_write_seconds_ago : null;
    var timeoutS = (typeof job.timeout_s === "number") ? job.timeout_s : null;

    elActivityPanel.classList.remove("stall-warn", "stall-bad");
    if (lastWrite !== null) {
      heartbeatBits.push("last output " + formatHeartbeat(lastWrite) + " ago");
      if (timeoutS) {
        if (lastWrite > timeoutS * 3) {
          elActivityPanel.classList.add("stall-bad");
          heartbeatBits.push("looks stalled");
        } else if (lastWrite > timeoutS * 2) {
          elActivityPanel.classList.add("stall-warn");
          heartbeatBits.push("may be stuck");
        }
      }
    }

    // Label: kind + total runtime + heartbeat. Runtime is a stopwatch
    // ("started 4m ago"); heartbeat is the liveness signal ("last output
    // 13s ago"). They answer different questions — one says how long, the
    // other says whether it's still alive — so both earn their space.
    var label = (job.kind || "benchmark");
    var startedAgo = (function() {
      try {
        var t = new Date(job.created_at).getTime();
        if (isNaN(t)) return null;
        var s = Math.max(0, (Date.now() - t) / 1000);
        return formatHeartbeat(s);
      } catch (e) { return null; }
    })();
    if (startedAgo) label += " · started " + startedAgo + " ago";
    if (heartbeatBits.length) {
      label += " · " + heartbeatBits.join(" · ");
    }
    elTerminalLabel.textContent = label;

    elJobActions.classList.remove("hidden");
    elJobLog.classList.remove("hidden");
    elJobLog.textContent = logText || "Waiting for output…";
    elJobLog.scrollTop = elJobLog.scrollHeight;
  }

  /** Format a duration in seconds as "4s", "47s", "3m 12s", "1h 4m". */
  function formatHeartbeat(seconds) {
    if (seconds < 60) return Math.round(seconds) + "s";
    if (seconds < 3600) {
      var m = Math.floor(seconds / 60);
      var s = Math.round(seconds % 60);
      return m + "m" + (s ? " " + s + "s" : "");
    }
    var h = Math.floor(seconds / 3600);
    var rm = Math.floor((seconds % 3600) / 60);
    return h + "h" + (rm ? " " + rm + "m" : "");
  }

  async function refreshJobs() {
    jobs = await fetchJson("/api/jobs");
    var running = jobs.find(function(j) { return j.status === "running"; });
    var latest = running || jobs[0] || null;

    var logText = "";
    if (running) {
      try {
        var logData = await fetchJson("/api/jobs/" + encodeURIComponent(running.job_id) + "/log?tail=250");
        logText = logData.log || "";
      } catch (_) {
        logText = "Failed to load log.";
      }
    }

    updateJobState(latest, logText);

    if (lastRunningJobId && !running) {
      await refreshRuns();
      if (runs.length && !activeRunId) {
        activeRunId = runs[0].run_id;
        await loadRun(activeRunId);
      }
    }
    lastRunningJobId = running ? running.job_id : null;
  }

  async function refreshRuns() {
    runs = await fetchJson("/api/runs");
    renderRuns();
  }

  // ── Start / cancel ──

  function buildRequestBody() {
    var preset = BENCH_PRESETS[elBenchMode.value] || BENCH_PRESETS.standard;
    var provider = currentProvider();
    var body = {
      server: (elServer.value || "").trim(),
      mode: preset.mode,
      sample_size: preset.sample_size || undefined,
      timeout: Number(elTimeout.value),
      delay: Number(elDelay.value),
      difficulty: preset.difficulty || undefined,
      test_set: preset.test_set || undefined,
      input_format: "csv",
      csv_dir: "data/csv",
      include_benign: preset.include_benign || undefined,
      provider: provider,
    };

    if (provider === "anthropic" && elAnthropicApiKey) {
      var key = (elAnthropicApiKey.value || "").trim();
      if (key) body.anthropic_api_key = key;
    }
    if (provider === "openai" && elOpenaiApiKey) {
      var oaiKey = (elOpenaiApiKey.value || "").trim();
      if (oaiKey) body.openai_api_key = oaiKey;
    }

    body.model = elModelSelect.value;
    return body;
  }

  // Pre-flight statuses that must BLOCK the run (the model can't be used as-is).
  // `timeout` is intentionally NOT here — a slow model is a soft warning, not a block.
  var PREFLIGHT_HARD = {
    unreachable: 1, auth_failed: 1, model_not_found: 1, error: 1, invalid_config: 1,
  };

  /** Decide whether the pre-flight result allows the run to start; updates status. */
  function preflightAllowsStart(pf) {
    if (!pf || typeof pf !== "object" || !pf.status) {
      setStatus("Pre-flight unavailable — starting anyway.");
      return true;
    }
    if (pf.status === "ok") {
      var ready = "Model ready";
      if (pf.latency_s) ready += " · responded in " + pf.latency_s + "s";
      setStatus(ready, "good");
      return true;
    }
    if (PREFLIGHT_HARD[pf.status]) {
      setStatus("Pre-flight failed: " + (pf.message || pf.status), "error");
      window.alert("Pre-flight check failed (" + pf.status + "):\n\n" +
                   (pf.message || "") + "\n\nThe run was not started.");
      return false;
    }
    // Soft (timeout = slow model, no_verdict = format) — warn and let the user decide.
    setStatus("Pre-flight warning: " + (pf.message || pf.status));
    return window.confirm("Pre-flight warning (" + pf.status + "):\n\n" +
                          (pf.message || "") + "\n\nRun anyway?");
  }

  async function startRun() {
    if (!elModelSelect.value) {
      window.alert("Select a model first.");
      return;
    }

    elStartRun.disabled = true;
    try {
      var body = buildRequestBody();

      // Pre-flight: probe the model once before committing to a long run.
      setStatus("Pre-flight: checking model…");
      var pf;
      try {
        pf = await fetchJson("/api/preflight", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        });
      } catch (e) {
        pf = null;  // endpoint failure (not the model) — treated as permissive
      }
      if (!preflightAllowsStart(pf)) return;

      var data = await fetchJson("/api/run/detect", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      activeJobId = data.job_id;
      lastRunningJobId = data.job_id;
      await refreshJobs();
      await refreshRuns();
    } catch (error) {
      window.alert(error.message || String(error));
    } finally {
      elStartRun.disabled = false;
    }
  }

  async function cancelActiveJob() {
    if (!activeJobId) return;
    try {
      await fetchJson("/api/jobs/" + encodeURIComponent(activeJobId) + "/cancel", { method: "POST" });
      await refreshJobs();
    } catch (error) {
      window.alert(error.message || String(error));
    }
  }

  function resetModelsForServerChange() {
    modelCache = [];
    setSelectOptions(elModelSelect, [], "Fetch models first");
    setStatus("Server changed. Fetch models to refresh the list.");
  }

  async function refreshAll() {
    await Promise.all([refreshRuns(), refreshJobs()]);
    // Do NOT auto-open a run on load/refresh — the result panel stays on its
    // "Select a run" placeholder until the user explicitly clicks one in
    // Recent runs. (A just-finished run is still auto-shown by the job poller.)
  }

  // ── Bind events ──

  elFetchModels.addEventListener("click", function () { loadModels(false); });
  elStartRun.addEventListener("click", startRun);
  elRefreshRuns.addEventListener("click", refreshAll);
  elClearAllRuns.addEventListener("click", deleteAllRuns);
  elRefreshEverything.addEventListener("click", refreshAll);
  elCancelJob.addEventListener("click", cancelActiveJob);
  elServer.addEventListener("change", resetModelsForServerChange);
  if (elProvider) elProvider.addEventListener("change", syncProvider);
  if (elAnthropicApiKey) {
    elAnthropicApiKey.addEventListener("change", function () {
      try { localStorage.setItem("forcast.anthropic_key", elAnthropicApiKey.value || ""); } catch (e) {}
      resetModelsForProviderChange();
    });
  }
  if (elOpenaiApiKey) {
    elOpenaiApiKey.addEventListener("change", function () {
      try { localStorage.setItem("forcast.openai_key", elOpenaiApiKey.value || ""); } catch (e) {}
      resetModelsForProviderChange();
    });
  }

  function _triggerDownload(url) {
    var a = document.createElement("a");
    a.href = url;
    a.rel = "noopener";
    a.style.display = "none";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  }

  if (elDownloadPdfBtn) {
    elDownloadPdfBtn.addEventListener("click", function() {
      var manifest = elDownloadPdfBtn.dataset.manifest;
      if (!manifest) return;
      _triggerDownload("/api/runs/" + encodeURIComponent(manifest) + "/pdf");
    });
  }

  if (elDownloadXlsxBtn) {
    elDownloadXlsxBtn.addEventListener("click", function() {
      var manifest = elDownloadXlsxBtn.dataset.manifest;
      if (!manifest) return;
      _triggerDownload("/api/runs/" + encodeURIComponent(manifest) + "/xlsx");
    });
  }

  // Restore last-used provider + API key from localStorage.
  try {
    var savedProvider = localStorage.getItem("forcast.provider");
    if (savedProvider && elProvider) elProvider.value = savedProvider;
    var savedKey = localStorage.getItem("forcast.anthropic_key");
    if (savedKey && elAnthropicApiKey) elAnthropicApiKey.value = savedKey;
    var savedOaiKey = localStorage.getItem("forcast.openai_key");
    if (savedOaiKey && elOpenaiApiKey) elOpenaiApiKey.value = savedOaiKey;
  } catch (e) {}

  syncProvider();

  refreshAll()
    .catch(function (error) {
      setStatus(error.message || String(error), "error");
    })
    .finally(function () {
      loadModels(true);
    });

  // Adaptive polling: 3s when a job is running, 30s when idle.
  // Pauses entirely when the tab is hidden.
  var pollTimer = null;

  function schedulePoll() {
    if (pollTimer) clearTimeout(pollTimer);
    var interval = lastRunningJobId ? 3000 : 30000;
    pollTimer = setTimeout(function () {
      refreshJobs().catch(function () {}).then(schedulePoll);
    }, interval);
  }

  document.addEventListener("visibilitychange", function () {
    if (document.hidden) {
      if (pollTimer) { clearTimeout(pollTimer); pollTimer = null; }
    } else {
      refreshJobs().catch(function () {}).then(schedulePoll);
    }
  });

  schedulePoll();
})();
