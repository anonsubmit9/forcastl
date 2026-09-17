#!/usr/bin/env python3
"""
HTML Report Generator for Detection Mode

Creates comprehensive, polished HTML reports with full transparency.
"""

import html
from datetime import datetime
from pathlib import Path
from typing import List, Dict

from forcastl import config


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MITRE ATT&CK LLM Detection Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}

        /* === Summary === */
        .summary {{
            background: #ecf0f1;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .summary-group {{
            margin-bottom: 18px;
        }}
        .summary-group:last-child {{
            margin-bottom: 0;
        }}
        .summary-group-label {{
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #7f8c8d;
            margin-bottom: 8px;
            padding-bottom: 4px;
            border-bottom: 2px solid #bdc3c7;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 10px;
        }}
        .stat {{
            text-align: center;
            padding: 12px 8px;
            background: white;
            border-radius: 5px;
        }}
        .stat-value {{
            font-size: 28px;
            font-weight: bold;
            color: #3498db;
        }}
        .stat-label {{
            color: #7f8c8d;
            font-size: 13px;
            margin-top: 4px;
        }}

        /* === File Results === */
        .file-result {{
            border: 1px solid #ddd;
            margin: 15px 0;
            border-radius: 5px;
            overflow: hidden;
        }}
        .file-header {{
            background: #34495e;
            color: white;
            padding: 0;
            cursor: pointer;
        }}
        .file-header:hover {{
            background: #2c3e50;
        }}
        .file-header-top {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px 15px 4px 15px;
        }}
        .file-header-metrics {{
            display: flex;
            gap: 18px;
            padding: 2px 15px 10px 15px;
            font-size: 13px;
            color: rgba(255,255,255,0.75);
        }}
        .file-header-metrics span {{
            white-space: nowrap;
        }}
        .file-content {{
            padding: 20px;
            display: none;
        }}
        .file-content.expanded {{
            display: block;
        }}
        .file-content-grid {{
            display: grid;
            grid-template-columns: 3fr 2fr;
            gap: 20px;
        }}
        @media (max-width: 900px) {{
            .file-content-grid {{
                grid-template-columns: 1fr;
            }}
        }}

        /* === Badges === */
        .detection-badge {{
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 14px;
        }}
        .badge-malicious {{
            background: #e74c3c;
            color: white;
        }}
        .badge-benign {{
            background: #2ecc71;
            color: white;
        }}
        .badge-error {{
            background: #e67e22;
            color: white;
        }}

        /* === Sections === */
        .section {{
            margin: 15px 0;
            padding: 15px;
            background: #f9f9f9;
            border-left: 4px solid #3498db;
            border-radius: 0 4px 4px 0;
        }}
        .section:first-child {{
            margin-top: 0;
        }}
        .section-title {{
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 10px;
        }}
        pre {{
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
            max-height: 500px;
            overflow-y: auto;
        }}

        /* === Ground Truth Table === */
        .gt-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0;
            table-layout: fixed;
        }}
        .gt-table th {{
            background: #34495e;
            color: white;
            padding: 10px;
            text-align: left;
        }}
        .gt-table th:nth-child(1) {{ width: 15%; }}
        .gt-table th:nth-child(2) {{ width: 30%; }}
        .gt-table th:nth-child(3) {{ width: 30%; }}
        .gt-table th:nth-child(4) {{ width: 25%; }}
        .gt-table td {{
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #ddd;
            overflow: hidden;
            text-overflow: ellipsis;
        }}
        .gt-table tr:nth-child(even) {{
            background: #f4f6f8;
        }}
        .gt-row-low {{
            border-left: 3px solid #e74c3c;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0;
        }}
        th, td {{
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background: #34495e;
            color: white;
        }}

        /* === Scores === */
        .score-good {{ color: #27ae60; font-weight: bold; }}
        .score-medium {{ color: #f39c12; font-weight: bold; }}
        .score-bad {{ color: #e74c3c; font-weight: bold; }}
        .validation-pass {{ color: #27ae60; }}
        .validation-fail {{ color: #e74c3c; }}
        .grade-badge {{
            display: inline-block;
            width: 36px;
            height: 36px;
            line-height: 36px;
            text-align: center;
            border-radius: 50%;
            font-weight: bold;
            font-size: 18px;
            color: white;
        }}
        .grade-badge-sm {{
            display: inline-block;
            width: 22px;
            height: 22px;
            line-height: 22px;
            text-align: center;
            border-radius: 50%;
            font-weight: bold;
            font-size: 12px;
            color: white;
            vertical-align: middle;
        }}
        .grade-A {{ background: #27ae60; }}
        .grade-B {{ background: #2ecc71; }}
        .grade-C {{ background: #f39c12; }}
        .grade-D {{ background: #e74c3c; }}
        .score-bar {{
            display: flex;
            height: 24px;
            border-radius: 4px;
            overflow: hidden;
            margin: 8px 0;
        }}
        .score-bar-segment {{
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 11px;
            font-weight: bold;
            color: white;
            min-width: 36px;
            overflow: hidden;
            cursor: default;
        }}
        .seg-extraction {{ background: #3498db; }}
        .seg-interpretation {{ background: #9b59b6; }}
        .seg-hallucination {{ background: #1abc9c; }}
        .seg-reasoning {{ background: #e67e22; }}

        /* === Hallucination Pills === */
        .hall-pill {{
            display: inline-block;
            background: #fdecea;
            color: #c0392b;
            border: 1px solid #e74c3c;
            border-radius: 12px;
            padding: 2px 10px;
            margin: 3px;
            font-size: 12px;
            font-weight: 500;
        }}

        /* === Buttons === */
        .toggle-btn {{
            background: #3498db;
            color: white;
            border: none;
            padding: 8px 15px;
            border-radius: 4px;
            cursor: pointer;
            margin: 3px;
            font-size: 13px;
        }}
        .toggle-btn:hover {{
            background: #2980b9;
        }}
        .filter-btn {{
            background: #ecf0f1;
            color: #2c3e50;
            border: 1px solid #bdc3c7;
            padding: 6px 14px;
            border-radius: 4px;
            cursor: pointer;
            margin: 3px;
            font-size: 13px;
            transition: all 0.15s;
        }}
        .filter-btn:hover {{
            background: #d5dbdb;
        }}
        .filter-btn.active {{
            background: #3498db;
            color: white;
            border-color: #3498db;
        }}
        .filter-count {{
            display: inline-block;
            background: rgba(0,0,0,0.15);
            border-radius: 10px;
            padding: 0 6px;
            font-size: 11px;
            margin-left: 4px;
            min-width: 16px;
            text-align: center;
        }}
        .filter-btn.active .filter-count {{
            background: rgba(255,255,255,0.25);
        }}
        .toolbar {{
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 8px;
            margin: 20px 0;
            position: sticky;
            top: 0;
            z-index: 100;
            background: white;
            padding: 10px 0;
            border-bottom: 1px solid transparent;
            transition: border-color 0.2s, box-shadow 0.2s;
        }}
        .toolbar.stuck {{
            border-bottom-color: #ddd;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }}
        .toolbar-separator {{
            width: 1px;
            height: 28px;
            background: #bdc3c7;
            margin: 0 4px;
        }}
        .sort-select {{
            padding: 6px 10px;
            border: 1px solid #bdc3c7;
            border-radius: 4px;
            font-size: 13px;
            background: white;
            cursor: pointer;
        }}
        .results-counter {{
            font-size: 13px;
            color: #7f8c8d;
            margin-left: auto;
        }}
        .search-input {{
            padding: 6px 10px;
            border: 1px solid #bdc3c7;
            border-radius: 4px;
            font-size: 13px;
            width: 180px;
        }}
        .search-input:focus {{
            outline: none;
            border-color: #3498db;
            box-shadow: 0 0 0 2px rgba(52,152,219,0.2);
        }}

        /* === Misc === */
        .meta-info {{
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 20px 0;
        }}
        .tag-badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 11px;
            font-weight: bold;
            margin-left: 6px;
        }}
        .tag-easy {{ background: #2ecc71; color: white; }}
        .tag-medium {{ background: #f39c12; color: white; }}
        .tag-hard {{ background: #e74c3c; color: white; }}
        .tag-A {{ background: #3498db; color: white; }}
        .tag-B {{ background: #9b59b6; color: white; }}
        .tag-C {{ background: #e67e22; color: white; }}
        details > summary {{
            cursor: pointer;
            user-select: none;
        }}

        /* === Recommendations === */
        .recs-section {{ margin: 20px 0; }}
        .recs-section h2 {{ margin-bottom: 8px; }}
        .rec-card {{ padding: 12px 18px; border-radius: 5px; margin: 8px 0; border-left: 4px solid; }}
        .rec-critical {{ background: #fdf0f0; border-color: #e74c3c; }}
        .rec-warning {{ background: #fef9f0; border-color: #f39c12; }}
        .rec-info {{ background: #f0f7fd; border-color: #3498db; }}
        .rec-title {{ font-weight: bold; font-size: 14px; color: #2c3e50; }}
        .rec-category {{ display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: bold; text-transform: uppercase; margin-right: 8px; }}
        .rec-cat-configuration {{ background: #3498db; color: white; }}
        .rec-cat-quality {{ background: #9b59b6; color: white; }}
        .rec-cat-per_file {{ background: #e67e22; color: white; }}
        .rec-description {{ font-size: 13px; color: #555; margin-top: 5px; }}
        .rec-files {{ font-size: 12px; color: #7f8c8d; margin-top: 4px; font-family: monospace; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>MITRE ATT&CK LLM Detection Report</h1>

        <div class="meta-info">
            <strong>Test Configuration:</strong><br>
            Model: {model_name} &nbsp;|&nbsp;
            Context Window: {context_window} tokens &nbsp;|&nbsp;
            Max Output Tokens: {max_tokens} tokens &nbsp;|&nbsp;
            Input Mode: {input_mode} &nbsp;|&nbsp;
            Test Date: {test_date} &nbsp;|&nbsp;
            Files Tested: {total_files}
        </div>

        <div class="summary">
            <h2>Summary Statistics</h2>

            <div class="summary-group">
                <div class="summary-group-label">Detection Results</div>
                <div class="summary-grid">
                    <div class="stat">
                        <div class="stat-value">{total_files}</div>
                        <div class="stat-label">Total Files</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value" style="color: #e74c3c;">{malicious_count}</div>
                        <div class="stat-label">Detected Malicious</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value" style="color: #2ecc71;">{benign_count}</div>
                        <div class="stat-label">Detected Benign</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value" style="color: #e67e22;">{error_count}</div>
                        <div class="stat-label">Errors / Skipped</div>
                    </div>
                </div>
            </div>

            <div class="summary-group">
                <div class="summary-group-label">Quality Metrics</div>
                <div class="summary-grid">
                    <div class="stat">
                        <div class="stat-value" style="color: #2c3e50;">{avg_score:.1f}/20</div>
                        <div class="stat-label">Avg Score</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value" style="color: #f39c12;">{avg_alignment:.1f}%</div>
                        <div class="stat-label">Avg Alignment</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value">{avg_confidence:.1f}%</div>
                        <div class="stat-label">Avg Confidence</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value">{grade_distribution}</div>
                        <div class="stat-label">Grade Distribution</div>
                    </div>
                </div>
            </div>

            <div class="summary-group">
                <div class="summary-group-label">Issues</div>
                <div class="summary-grid">
                    <div class="stat">
                        <div class="stat-value" style="color: #e74c3c;">{avg_hallucination_rate:.1f}%</div>
                        <div class="stat-label">Avg Hallucination Rate</div>
                    </div>
                </div>
            </div>
        </div>

        {recommendations_html}

        <div class="toolbar">
            <button class="toggle-btn" onclick="expandAll()">Expand All</button>
            <button class="toggle-btn" onclick="collapseAll()">Collapse All</button>

            <div class="toolbar-separator"></div>

            <button class="filter-btn active" onclick="filterResults('all', this)">All <span class="filter-count">{total_files}</span></button>
            <button class="filter-btn" onclick="filterResults('malicious', this)">Malicious <span class="filter-count">{malicious_count}</span></button>
            <button class="filter-btn" onclick="filterResults('benign', this)">Benign <span class="filter-count">{benign_count}</span></button>
            <button class="filter-btn" onclick="filterResults('error', this)">Errors <span class="filter-count">{error_count}</span></button>

            <div class="toolbar-separator"></div>

            <select class="sort-select" onchange="sortResults(this.value)">
                <option value="default">Sort: File Order</option>
                <option value="score-desc">Score (High to Low)</option>
                <option value="score-asc">Score (Low to High)</option>
                <option value="alignment-desc">Alignment (High to Low)</option>
                <option value="filename">Filename (A-Z)</option>
            </select>

            <div class="toolbar-separator"></div>

            <input type="text" class="search-input" id="filename-search"
                   placeholder="Search filename..." oninput="searchFilename(this.value)">

            <span class="results-counter" id="results-counter">Showing {total_files} of {total_files}</span>
        </div>

        <h2>Individual File Results</h2>
        <p style="font-size:12px;color:#888;margin:-5px 0 10px 0;">Score bar legend: <span style="color:#3498db;font-weight:bold;">E</span>=Extraction(6) <span style="color:#9b59b6;font-weight:bold;">I</span>=Interpretation(6) <span style="color:#1abc9c;font-weight:bold;">H</span>=NoHallucination(4) <span style="color:#e67e22;font-weight:bold;">R</span>=Reasoning(4)</p>
        <div id="results-container">
        {file_results}
        </div>

        <h2>Appendix</h2>
        <div class="section">
            <div class="section-title">Test Set &amp; Difficulty Definitions</div>
            <details>
                <summary><strong>Click to expand classification definitions</strong></summary>
                <div style="margin-top:10px;color:#2c3e50;font-size:14px;line-height:1.45;">
                    <p><strong>Test Set</strong> categorises each test case by the type of challenge it presents to the LLM:</p>
                    <ul style="margin:4px 0 12px 20px;">
                        <li><strong>A &mdash; Known Pattern</strong>: Straightforward attacks with clear signatures. Default category.</li>
                        <li><strong>B &mdash; Obfuscated</strong>: Commands or filenames contain obfuscation indicators (base64, encoded commands, tools like Empire/CobaltStrike/Meterpreter). The LLM must see through the obfuscation.</li>
                        <li><strong>C &mdash; Noise-heavy</strong>: Low signal-to-noise ratio (&gt;15 events, &lt;30% are attack-relevant). The LLM must find the needle in the haystack.</li>
                    </ul>
                    <p><strong>Difficulty</strong> is based on the signal-to-noise ratio of each EVTX file (what fraction of events contain ground-truth evidence):</p>
                    <ul style="margin:4px 0 12px 20px;">
                        <li><strong>Easy</strong>: signal ratio &ge; 50%, or the file has &le; 10 events total.</li>
                        <li><strong>Medium</strong>: everything between easy and hard.</li>
                        <li><strong>Hard</strong>: signal ratio &lt; 15% and &gt; 20 events total.</li>
                    </ul>
                </div>
            </details>
        </div>
        <div class="section">
            <div class="section-title">Scoring Definitions (20-Point Composite)</div>
            <details>
                <summary><strong>Click to expand scoring rubric</strong></summary>
                <div style="margin-top:10px;color:#2c3e50;font-size:14px;line-height:1.45;">
                    <p><strong>Total (20)</strong> = Extraction (6) + Interpretation (6) + NoHallucination (4) + Reasoning (4).</p>
                    <p><strong>Extraction (0-6)</strong>: If ground truth is available, this is proportional to the ground-truth alignment score:
                    <code>Extraction = 6 * (Alignment% / 100)</code>. If ground truth is not available, a structure-based heuristic is used.</p>
                    <p><strong>Interpretation (0-6)</strong>:
                    +4 if MALICIOUS YES/NO matches ground truth,
                    +1 if at least 2 evidence fields are populated,
                    +1 if the explanation is consistent with the classification.</p>
                    <p><strong>NoHallucination (0-4)</strong>: Starts at 4 and decreases proportionally to the fraction of claimed evidence items
                    that do not exist in the event data provided to the LLM in the prompt.</p>
                    <p><strong>Reasoning (0-4)</strong>:
                    +1 if the explanation is substantive,
                    +1 if it references at least 2 evidence items,
                    +1 if it is consistent with the MALICIOUS classification,
                    +1 if it uses security-domain language.</p>
                    <p><strong>Alignment%</strong>: Field-by-field match of the LLM-extracted evidence against ground truth, scoped to the evidence present
                    in the event data that was actually sent to the LLM (so the model is not penalized for evidence it could not see).</p>
                    <p><strong>Grade</strong>: A &ge; 17, B &ge; 14, C &ge; 10, else D.</p>
                </div>
            </details>
        </div>
    </div>

    <script>
        function toggleFile(id) {{
            const content = document.getElementById('content-' + id);
            content.classList.toggle('expanded');
        }}

        function expandAll() {{
            document.querySelectorAll('.file-content').forEach(el => {{
                el.classList.add('expanded');
            }});
        }}

        function collapseAll() {{
            document.querySelectorAll('.file-content').forEach(el => {{
                el.classList.remove('expanded');
            }});
        }}

        var _activeFilter = 'all';
        var _searchText = '';

        function _applyFilters() {{
            const all = document.querySelectorAll('.file-result');
            let visible = 0;
            all.forEach(el => {{
                const catMatch = _activeFilter === 'all' || el.dataset.category === _activeFilter;
                const nameMatch = !_searchText || (el.dataset.filename || '').toLowerCase().includes(_searchText);
                if (catMatch && nameMatch) {{
                    el.style.display = '';
                    visible++;
                }} else {{
                    el.style.display = 'none';
                }}
            }});
            const counter = document.getElementById('results-counter');
            if (counter) counter.textContent = 'Showing ' + visible + ' of ' + all.length;
        }}

        function filterResults(category, btn) {{
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            if (btn) btn.classList.add('active');
            _activeFilter = category;
            _applyFilters();
        }}

        function searchFilename(value) {{
            _searchText = value.toLowerCase().trim();
            _applyFilters();
        }}

        // Detect toolbar stuck state
        (function() {{
            const toolbar = document.querySelector('.toolbar');
            if (!toolbar) return;
            const observer = new IntersectionObserver(
                ([e]) => toolbar.classList.toggle('stuck', e.intersectionRatio < 1),
                {{ threshold: [1], rootMargin: '-1px 0px 0px 0px' }}
            );
            observer.observe(toolbar);
        }})();

        function sortResults(field) {{
            const container = document.getElementById('results-container');
            const items = Array.from(container.querySelectorAll('.file-result'));
            items.sort((a, b) => {{
                if (field === 'score-desc') {{
                    return parseFloat(b.dataset.score || 0) - parseFloat(a.dataset.score || 0);
                }} else if (field === 'score-asc') {{
                    return parseFloat(a.dataset.score || 0) - parseFloat(b.dataset.score || 0);
                }} else if (field === 'alignment-desc') {{
                    return parseFloat(b.dataset.alignment || 0) - parseFloat(a.dataset.alignment || 0);
                }} else if (field === 'filename') {{
                    return (a.dataset.filename || '').localeCompare(b.dataset.filename || '');
                }} else {{
                    return parseInt(a.dataset.index || 0) - parseInt(b.dataset.index || 0);
                }}
            }});
            items.forEach(item => container.appendChild(item));
        }}
    </script>
</body>
</html>
"""


def _build_rec_card(rec: dict) -> str:
    """Render a single recommendation card as HTML."""
    sev = html.escape(rec.get("severity", "info"))
    cat = html.escape(rec.get("category", ""))
    title = html.escape(rec.get("title", ""))
    desc = html.escape(rec.get("description", ""))
    files = rec.get("affected_files", [])

    files_html = ""
    if files:
        file_list = ", ".join(html.escape(f) for f in files)
        files_html = f'<div class="rec-files">Affected: {file_list}</div>'

    cat_label = html.escape(rec.get("category", "").replace("_", " "))
    return (
        f'<div class="rec-card rec-{sev}">'
        f'<span class="rec-category rec-cat-{cat}">{cat_label}</span> '
        f'<span class="rec-title">{title}</span>'
        f'<div class="rec-description">{desc}</div>'
        f'{files_html}'
        f'</div>'
    )


def _build_recommendations_html(recommendations: list) -> str:
    """Build styled HTML for recommendations (critical/warning) and observations (info)."""
    if not recommendations:
        return ""
    recs = [r for r in recommendations if r.get("severity") != "info"]
    obs = [r for r in recommendations if r.get("severity") == "info"]

    parts = []
    if recs:
        parts.append(
            '<div class="recs-section">'
            '<h2>Recommendations</h2>'
            + "\n".join(_build_rec_card(r) for r in recs)
            + '</div>'
        )
    if obs:
        parts.append(
            '<div class="recs-section">'
            '<h2>Observations</h2>'
            + "\n".join(_build_rec_card(r) for r in obs)
            + '</div>'
        )
    return "\n".join(parts)


def _get_file_tags(filename: str) -> tuple:
    """Look up difficulty and test_set tags from ground truth or metadata."""
    try:
        import json as _json
        gt_path = config.GROUND_TRUTH_FILE
        if not hasattr(_get_file_tags, '_gt_cache'):
            try:
                with open(gt_path, 'r', encoding='utf-8') as f:
                    _get_file_tags._gt_cache = _json.load(f).get('files', {})
            except Exception:
                _get_file_tags._gt_cache = {}
        entry = _get_file_tags._gt_cache.get(filename, {})
        return entry.get('difficulty', ''), entry.get('test_set', '')
    except Exception:
        return '', ''


def _is_error_result(result: Dict) -> str:
    """Check if a result represents an error/failed analysis.

    Returns a human label ('Parse Error', 'Context Exceeded', 'Timeout', 'Error')
    or empty string if the result is normal.
    """
    status = result.get('status', '')
    if status == 'context_exceeded':
        return 'Context Exceeded'
    if status == 'error':
        llm_resp = result.get('llm_response', '')
        if 'timed out' in llm_resp.lower():
            return 'Timeout'
        if 'parse error' in llm_resp.lower() or 'failed to parse' in llm_resp.lower():
            return 'Parse Error'
        return 'Error'
    return ''


_GRADE_COLORS = {
    'A': '#27ae60',
    'B': '#2ecc71',
    'C': '#f39c12',
    'D': '#e74c3c',
}


def _build_tag_badges(filename: str) -> str:
    """Build tag badge HTML for a filename."""
    difficulty_tag, test_set_tag = _get_file_tags(filename)
    tag_badges = ""
    if difficulty_tag:
        tag_badges += f'<span class="tag-badge tag-{difficulty_tag}">{difficulty_tag.upper()}</span>'
    if test_set_tag:
        set_labels = {'A': 'A: Known', 'B': 'B: Obfuscated', 'C': 'C: Noise'}
        tag_badges += f'<span class="tag-badge tag-{test_set_tag}">{set_labels.get(test_set_tag, test_set_tag)}</span>'
    return tag_badges


def generate_file_result_html(result: Dict, index: int) -> str:
    """Generate HTML for a single file result"""
    detection = result.get('detection', {})
    parsed = detection.get('parsed', {})
    validation = detection.get('validation', {})
    alignment = detection.get('alignment', {})

    filename = Path(result.get('file_path', 'Unknown')).name
    tag_badges = _build_tag_badges(filename)
    response_time = result.get('response_time', 0)

    # Check for error/failed results — render condensed block
    error_label = _is_error_result(result)
    if error_label:
        error_msg = html.escape(result.get('llm_response', 'No details available'))
        return f"""
    <div class="file-result" style="border-left: 4px solid #e67e22;"
         data-category="error" data-score="0" data-alignment="0"
         data-filename="{html.escape(filename)}" data-index="{index}">
        <div class="file-header" onclick="toggleFile({index})">
            <div class="file-header-top">
                <div><strong>{index + 1}. {filename}</strong>{tag_badges}</div>
                <div><span class="detection-badge badge-error">ERROR</span></div>
            </div>
            <div class="file-header-metrics">
                <span>{error_label}</span>
            </div>
        </div>
        <div class="file-content" id="content-{index}">
            <div class="section" style="border-left-color: #e67e22;">
                <div class="section-title">Error Details &mdash; {error_label}</div>
                <pre>{error_msg}</pre>
            </div>
        </div>
    </div>
    """

    # --- Normal result ---

    # Detection badge
    is_malicious = detection.get('is_malicious', False)
    badge_class = 'badge-malicious' if is_malicious else 'badge-benign'
    badge_text = 'MALICIOUS' if is_malicious else 'BENIGN'
    category = 'malicious' if is_malicious else 'benign'

    # Confidence and alignment
    confidence = detection.get('confidence', 0)
    align_score = alignment.get('score', 0) if alignment else 0

    # Score breakdown
    score_bd = detection.get('score_breakdown', {})
    total_score = score_bd.get('total', 0) if score_bd else 0
    grade = score_bd.get('grade', '?') if score_bd else '?'

    # Grade border color
    border_color = _GRADE_COLORS.get(grade, '#95a5a6')

    # HTML-escape response and prompt
    escaped_response = html.escape(result.get('llm_response', 'No response'))
    escaped_prompt = html.escape(result.get('prompt', 'No prompt stored'))

    # --- Header metrics line ---
    grade_badge_sm = f'<span class="grade-badge-sm grade-{grade}">{grade}</span>' if grade != '?' else ''
    metrics_parts = [
        f"<span>Confidence: {confidence:.0f}%</span>",
        f"<span>Alignment: {align_score:.0f}%</span>",
    ]
    if score_bd:
        metrics_parts.append(f"<span>Score: {total_score}/20 {grade_badge_sm}</span>")
    metrics_parts.append(f"<span>{response_time:.1f}s</span>")
    metrics_html = '\n                '.join(metrics_parts)

    # --- Left column: Score, Alignment, Hallucination, Reasoning ---

    # Score breakdown section
    score_html = ""
    if score_bd:
        ext = score_bd.get('extraction', 0)
        interp = score_bd.get('interpretation', 0)
        hall_s = score_bd.get('hallucination', 0)
        reas = score_bd.get('reasoning', 0)

        bar_total = 20
        segments = []
        if ext > 0:
            segments.append(f'<div class="score-bar-segment seg-extraction" style="width:{ext / bar_total * 100}%" title="Extraction: {ext}/6">E:{ext}</div>')
        if interp > 0:
            segments.append(f'<div class="score-bar-segment seg-interpretation" style="width:{interp / bar_total * 100}%" title="Interpretation: {interp}/6">I:{interp}</div>')
        if hall_s > 0:
            segments.append(f'<div class="score-bar-segment seg-hallucination" style="width:{hall_s / bar_total * 100}%" title="Hallucination: {hall_s}/4">H:{hall_s}</div>')
        if reas > 0:
            segments.append(f'<div class="score-bar-segment seg-reasoning" style="width:{reas / bar_total * 100}%" title="Reasoning: {reas}/4">R:{reas}</div>')

        bar_html = '\n                '.join(segments)
        score_html = f'''<div class="section">
                <div class="section-title">Score Breakdown</div>
                <p><span class="grade-badge grade-{grade}">{grade}</span> <strong>{total_score}/20</strong></p>
                <div class="score-bar">
                    {bar_html}
                </div>
            </div>'''
    else:
        score_html = '''<div class="section">
                <div class="section-title">Score Breakdown</div>
                <p>No score data available</p>
            </div>'''

    # Ground truth alignment table
    gt_html = ""
    if alignment and 'field_matches' in alignment:
        rows = ""
        # Malicious field — benign samples are named BENIGN-* by convention; the
        # rest of the corpus is malicious.
        expected_mal = "NO" if filename.startswith("BENIGN-") else "YES"
        detected_mal = html.escape(str(parsed.get('malicious', '?')))
        match_icon = "&#10003;" if alignment.get('malicious_match') else "&#10007;"
        rows += f"<tr><td>Malicious</td><td>{expected_mal}</td><td>{detected_mal}</td><td>{match_icon}</td></tr>"

        for field_name in ['event_ids', 'processes', 'accounts', 'commands', 'network', 'registry']:
            if field_name in alignment['field_matches']:
                field_data = alignment['field_matches'][field_name]
                expected = html.escape(', '.join(str(e) for e in field_data.get('expected', [])[:3]))
                detected = html.escape(', '.join(str(e) for e in field_data.get('detected', [])[:3]))
                score = field_data.get('score', 0)

                score_class = 'score-good' if score >= 80 else ('score-medium' if score >= 50 else 'score-bad')
                row_class = ' class="gt-row-low"' if score < 80 else ''
                field_label = html.escape(field_name.replace('_', ' ').title())
                rows += f"<tr{row_class}><td>{field_label}</td><td>{expected}</td><td>{detected}</td><td class='{score_class}'>{score:.0f}%</td></tr>"

        gt_html = f'''<div class="section">
                <div class="section-title">Ground Truth Alignment</div>
                <table class="gt-table"><tr><th>Field</th><th>Expected</th><th>LLM Detected</th><th>Score</th></tr>
                {rows}
                </table>
                <p><strong>Overall Alignment Score:</strong> {align_score:.1f}%</p>
            </div>'''
    else:
        gt_html = f'''<div class="section">
                <div class="section-title">Ground Truth Alignment</div>
                <p>No ground truth available</p>
                <p><strong>Overall Alignment Score:</strong> {align_score:.1f}%</p>
            </div>'''

    # Hallucination check
    hallucination = detection.get('hallucination', {})
    hall_html_content = ""
    if hallucination:
        h_total = hallucination.get('total_hallucinated', 0)
        h_claimed = hallucination.get('total_claimed', 0)
        h_score = hallucination.get('score', 4)
        hall_html_content = f'<p><strong>Score:</strong> {h_score}/4 ({h_total} fabricated out of {h_claimed} claimed)</p>'
        if h_total > 0:
            pills = []
            for field, items in hallucination.get('hallucinated', {}).items():
                if items:
                    label = html.escape(field.replace('_', ' ').title())
                    for item in items[:5]:
                        pills.append(f'<span class="hall-pill">{label}: {html.escape(str(item))}</span>')
            if pills:
                hall_html_content += '<div style="margin-top:6px;">' + '\n'.join(pills) + '</div>'
    else:
        hall_html_content = "<p>No hallucination data available</p>"

    hall_html = f'''<div class="section">
                <div class="section-title">Hallucination Check</div>
                {hall_html_content}
            </div>'''

    # Reasoning quality
    reasoning = detection.get('reasoning', {})
    if reasoning:
        r_score = reasoning.get('score', 0)
        r_details = ', '.join(reasoning.get('details', [])) or 'none'
        reasoning_content = f'<p><strong>Score:</strong> {r_score}/4 ({html.escape(r_details)})</p>'
    else:
        reasoning_content = "<p>No reasoning data available</p>"

    reasoning_html = f'''<div class="section">
                <div class="section-title">Reasoning Quality</div>
                {reasoning_content}
            </div>'''

    # --- Right column: LLM Response (collapsed), Validation, Prompt ---

    # Format warning
    format_warning = ""
    raw_response = result.get('llm_response', '')
    if 'WINDOWS EVENT LOG DATA:' in raw_response or '<Event xmlns=' in raw_response:
        format_warning = """
                <div class="section" style="border-left-color: #e67e22; background: #fef9f3;">
                    <div class="section-title" style="color: #e67e22;">Format Warning &mdash; XML Echo Detected</div>
                    <p>The LLM echoed back raw event data instead of providing a structured analysis.
                    This response should be treated as a <strong>format violation</strong>.</p>
                </div>"""

    # Structure validation
    structure_html = ""
    if validation:
        status = "&#10003; Valid" if validation.get('is_valid') else f"Issues: {html.escape(', '.join(validation.get('issues', [])))}"
        status_class = 'validation-pass' if validation.get('is_valid') else 'validation-fail'
        structure_html = f"<p class='{status_class}'><strong>Structure:</strong> {status}</p>"
        structure_html += f"<p><strong>Evidence Fields Populated:</strong> {validation.get('evidence_fields_populated', 0)}/6</p>"

    html_output = f"""
    <div class="file-result" style="border-left: 4px solid {border_color};"
         data-category="{category}" data-score="{total_score}"
         data-alignment="{align_score}" data-filename="{html.escape(filename)}" data-index="{index}">
        <div class="file-header" onclick="toggleFile({index})">
            <div class="file-header-top">
                <div><strong>{index + 1}. {filename}</strong>{tag_badges}</div>
                <div><span class="detection-badge {badge_class}">{badge_text}</span></div>
            </div>
            <div class="file-header-metrics">
                {metrics_html}
            </div>
        </div>
        <div class="file-content" id="content-{index}">
            <div class="file-content-grid">
                <div class="file-content-left">
                    {score_html}
                    {gt_html}
                    {hall_html}
                    {reasoning_html}
                </div>
                <div class="file-content-right">
                    <div class="section">
                        <div class="section-title">LLM Response</div>
                        <details>
                            <summary><strong>Click to view raw LLM response</strong></summary>
                            <pre>{escaped_response}</pre>
                        </details>
                    </div>
                    {format_warning}

                    <div class="section">
                        <div class="section-title">Validation Results</div>
                        {structure_html if structure_html else "<p>No validation data</p>"}
                    </div>

                    <div class="section">
                        <div class="section-title">Prompt Sent to LLM</div>
                        <details>
                            <summary><strong>Click to view full prompt</strong></summary>
                            <pre>{escaped_prompt}</pre>
                        </details>
                    </div>
                </div>
            </div>
        </div>
    </div>
    """
    return html_output



def generate_detection_html_report(
    test_results: List[Dict],
    model_name: str,
    context_window: int,
    max_tokens: int = None,
    output_dir: str = None,
    run_id: str = None,
    output_file: str = None,
    recommendations: list = None,
) -> str:
    """
    Generate comprehensive HTML report for detection mode results

    Args:
        test_results: List of detection results
        model_name: Name of the LLM model used
        context_window: Context window size
        output_dir: Directory to save report

    Returns:
        Path to generated HTML file
    """
    if output_dir is None:
        output_dir = str(config.OUTPUTS_DIR)

    # Calculate statistics — separate errors from valid results
    total_files = len(test_results)
    error_count = sum(1 for r in test_results if _is_error_result(r))
    valid_results = [r for r in test_results if not _is_error_result(r)]

    malicious_count = sum(1 for r in valid_results if r.get('detection', {}).get('is_malicious', False))
    benign_count = len(valid_results) - malicious_count

    alignments = [r.get('detection', {}).get('alignment', {}).get('score')
                 for r in valid_results if r.get('detection', {}).get('alignment')]
    alignments = [a for a in alignments if a is not None]
    avg_alignment = sum(alignments) / len(alignments) if alignments else 0

    confidences = [r.get('detection', {}).get('confidence', 0)
                  for r in valid_results if r.get('detection')]
    avg_confidence = sum(confidences) / len(confidences) if confidences else 0

    # Score breakdown stats
    scores = [r.get('detection', {}).get('score_breakdown', {}).get('total', 0)
              for r in valid_results if r.get('detection', {}).get('score_breakdown')]
    avg_score = sum(scores) / len(scores) if scores else 0

    grades = [r.get('detection', {}).get('score_breakdown', {}).get('grade', 'D')
              for r in valid_results if r.get('detection', {}).get('score_breakdown')]
    grade_counts = {g: grades.count(g) for g in ['A', 'B', 'C', 'D'] if grades.count(g) > 0}
    grade_distribution = ' '.join(f"{g}:{c}" for g, c in grade_counts.items()) if grade_counts else 'N/A'

    hall_rates = [r.get('detection', {}).get('hallucination', {}).get('ratio', 0)
                  for r in valid_results if r.get('detection', {}).get('hallucination')]
    avg_hallucination_rate = (sum(hall_rates) / len(hall_rates) * 100) if hall_rates else 0

    # Generate file results HTML
    file_results_html = ""
    for idx, result in enumerate(test_results):
        file_results_html += generate_file_result_html(result, idx)

    # Build recommendations HTML (generated upstream; fallback if called standalone)
    if recommendations is None:
        from forcastl.reporting.recommendations import generate_recommendations
        rec_config = {"context_window": context_window, "max_tokens": max_tokens or 0, "model_name": model_name}
        recommendations = generate_recommendations(test_results, rec_config)
    recommendations_html = _build_recommendations_html(recommendations)

    # Fill template
    html_content = HTML_TEMPLATE.format(
        model_name=model_name,
        context_window=context_window,
        max_tokens=('?' if max_tokens is None else max_tokens),
        input_mode="raw (full artefact; no sampling/capping)",
        test_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        total_files=total_files,
        malicious_count=malicious_count,
        benign_count=benign_count,
        avg_alignment=avg_alignment,
        avg_confidence=avg_confidence,
        avg_score=avg_score,
        grade_distribution=grade_distribution,
        avg_hallucination_rate=avg_hallucination_rate,
        error_count=error_count,
        file_results=file_results_html,
        recommendations_html=recommendations_html,
    )

    # Save to file
    import re
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    if output_file:
        out_path = Path(output_file)
    else:
        timestamp = run_id or datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_model = re.sub(r'[^\w\-.]', '_', model_name)
        out_path = Path(output_dir) / f'detection_report_{safe_model}_{timestamp}.html'

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

    return str(out_path)


def main():
    """Test the HTML report generator"""
    # Sample test data
    test_results = [
        {
            'file_path': 'test1.evtx',
            'llm_response': 'MALICIOUS: YES\nEVIDENCE:\n- Event IDs: 4625\nEXPLANATION: Failed logins',
            'prompt': 'Analyze this file...',
            'response_time': 2.5,
            'detection': {
                'is_malicious': True,
                'confidence': 100,
                'parsed': {'malicious': 'YES'},
                'validation': {'is_valid': True, 'evidence_fields_populated': 4, 'issues': []},
                'alignment': {
                    'score': 85,
                    'malicious_match': True,
                    'field_matches': {
                        'event_ids': {'expected': ['4625'], 'detected': ['4625'], 'score': 100}
                    }
                }
            }
        }
    ]

    output_file = generate_detection_html_report(
        test_results=test_results,
        model_name='foundation-sec-8b',
        context_window=8192
    )

    print(f"Test report generated: {output_file}")


if __name__ == "__main__":
    main()
