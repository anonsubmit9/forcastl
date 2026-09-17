"""File selection and filtering for test cases."""

from pathlib import Path
from typing import List, Dict, Optional
from colorama import Fore, Style

from forcastl.core.verdict import MIN_SAMPLES_FOR_VERDICT


class FileSelector:
    """Handles file selection, CSV lookup, and tag-based filtering."""

    def __init__(self, metadata: Dict, *, input_format: str = 'csv',
                 csv_dir: str = None, difficulty: str = None,
                 test_set: str = None, verbose: bool = False,
                 ground_truth_data: Dict = None,
                 include_benign: bool = False):
        self.metadata = metadata
        self.input_format = input_format
        self.csv_dir = csv_dir
        self.difficulty = difficulty
        self.test_set = test_set
        self.verbose = verbose
        self.ground_truth_data = ground_truth_data or {}
        # If set, sample mode reserves slots for all BENIGN-tactic files before
        # the per-tactic round-robin, so they're guaranteed to appear in the
        # sample even though BENIGN is a small bucket.
        self.include_benign = include_benign
        self.csv_lookup = {}
        if self.input_format == 'csv':
            self.csv_lookup = self._build_csv_lookup()

    def _find_csv_for_evtx(self, evtx_path: str) -> Optional[str]:
        """Find corresponding CSV file for an EVTX file in the csv_dir."""
        if not self.csv_dir:
            return None
        stem = Path(evtx_path).stem
        if self.csv_lookup:
            return self.csv_lookup.get(stem.lower())
        for csv_file in Path(self.csv_dir).rglob(f'{stem}.csv'):
            return str(csv_file)
        return None

    def _build_csv_lookup(self) -> Dict[str, str]:
        """Build fast stem->CSV path lookup for CSV input mode."""
        csv_root = Path(self.csv_dir) if self.csv_dir else None
        if not csv_root or not csv_root.exists():
            raise FileNotFoundError(f"CSV directory not found: {self.csv_dir}")

        lookup: Dict[str, str] = {}
        for csv_file in csv_root.rglob('*.csv'):
            stem = csv_file.stem.lower()
            if stem not in lookup:
                lookup[stem] = str(csv_file)

        print(f"{Fore.GREEN}[OK] Indexed {len(lookup)} CSV files for stem matching{Style.RESET_ALL}")
        return lookup

    def _filter_csv_compatible_files(self, files: Dict[str, Dict]) -> Dict[str, Dict]:
        """Exclude EVTX entries without matching CSV files when in CSV mode."""
        if self.input_format != 'csv':
            return files

        compatible: Dict[str, Dict] = {}
        missing = []
        for filename, file_info in files.items():
            evtx_path = file_info.get('full_path', '')
            if evtx_path and self._find_csv_for_evtx(evtx_path):
                compatible[filename] = file_info
            else:
                missing.append(filename)

        if missing:
            print(f"{Fore.YELLOW}[INFO] Skipping {len(missing)} files with no matching CSV in {self.csv_dir}{Style.RESET_ALL}")
            if self.verbose:
                preview = ', '.join(missing[:5])
                suffix = ' ...' if len(missing) > 5 else ''
                print(f"{Fore.YELLOW}       Missing CSV for: {preview}{suffix}{Style.RESET_ALL}")
        return compatible

    def _lookup_file_tag(self, filename: str, tag: str) -> Optional[str]:
        """Look up a tag (difficulty or test_set) from ground truth or metadata."""
        gt_data = self.ground_truth_data
        if filename in gt_data and tag in gt_data[filename]:
            return gt_data[filename][tag]
        meta_files = self.metadata.get('files', {})
        if filename in meta_files and tag in meta_files[filename]:
            return meta_files[filename][tag]
        return None

    def select_files(self, mode: str = None, sample_size: int = None) -> List[Dict]:
        """Select files to test"""
        all_files = self.metadata.get('files', {})
        files = {k: v for k, v in all_files.items() if not v.get('excluded', False)}
        excluded_count = len(all_files) - len(files)
        if excluded_count > 0:
            print(f"{Fore.YELLOW}[INFO] Skipping {excluded_count} excluded files from metadata{Style.RESET_ALL}")

        # Entries marked csv_only (synthesized benign CSVs without a real EVTX
        # backing file) are only usable in CSV input mode.
        if self.input_format != 'csv':
            before = len(files)
            files = {k: v for k, v in files.items() if not v.get('csv_only', False)}
            skipped = before - len(files)
            if skipped:
                print(f"{Fore.YELLOW}[INFO] Skipping {skipped} csv_only files (not applicable to evtx mode){Style.RESET_ALL}")

        files = self._filter_csv_compatible_files(files)
        # Apply difficulty/test_set filters to the POOL, before any sampling.
        # Filtering after selection silently shrank the sample: with 13 hard
        # files in the corpus, `--difficulty hard --sample-size 50` returned
        # only the hard files that happened to land in the 50-file sample.
        files = self._prefilter_by_tags(files)

        if mode is None:
            # Interactive mode
            print(f"\n{Fore.CYAN}Select Test Mode:{Style.RESET_ALL}")
            print("1. Test a single EVTX file")
            print("2. Quick test with sample files from each tactic")
            print("3. Complete test of all EVTX files")
            choice = input("\nSelect mode (1-3): ").strip()
        else:
            choice = {'single': '1', 'sample': '2', 'all': '3'}[mode]

        if choice == '1':
            if mode is not None:
                # Non-interactive: pick the first file
                first_file = next(iter(files.values()), None)
                return [first_file] if first_file else []
            # Interactive: List first 20 files
            file_list = list(files.items())[:20]
            for i, (filename, _) in enumerate(file_list, 1):
                print(f"{i:2d}. {filename}")

            try:
                idx = int(input("\nSelect file number: ")) - 1
                if 0 <= idx < len(file_list):
                    filename, file_info = file_list[idx]
                    return [file_info]
            except ValueError:
                pass
            return []

        elif choice == '2':
            # Sample test - spread evenly across tactics
            from collections import defaultdict
            tactic_files = defaultdict(list)
            for filename, file_info in files.items():
                tactic_id = file_info.get('tactic_id', 'unknown')
                tactic_files[tactic_id].append(file_info)

            max_files = sample_size or 20

            # When include_benign is set, reserve ALL BENIGN files up front
            # — never trim them to fit `max_files`. The semantics of the flag
            # are "always include the benigns so I can measure FP rate";
            # silently dropping benigns when sample_size is small would defeat
            # that. If max_files is smaller than the benign count, expand the
            # effective budget rather than starve attack files (the user is
            # asking for an FP measurement, not a min-cost run).
            reserved_benign = []
            benign_all = []
            if self.include_benign:
                # Identify benign by GROUND-TRUTH label (malicious == "NO") — the
                # same definition the verdict counts — rather than metadata
                # tactic_id, which can disagree for files relabeled after the fact
                # (Tier-1 review) or near-miss controls tagged with the tactic they
                # mimic. Pull the benigns out of their tactic buckets.
                def _is_benign(fi):
                    name = fi.get('file_name') or Path(fi.get('full_path', '')).name
                    entry = self.ground_truth_data.get(name)
                    if entry is not None:
                        return str(entry.get('malicious', '')).upper() == 'NO'
                    return fi.get('tactic_id') == 'BENIGN'
                for tid in list(tactic_files):
                    bucket = tactic_files[tid]
                    attack_only = [fi for fi in bucket if not _is_benign(fi)]
                    benign_all.extend(fi for fi in bucket if _is_benign(fi))
                    if attack_only:
                        tactic_files[tid] = attack_only
                    else:
                        del tactic_files[tid]

            # Difficulty-stratified selection: order every pool hard -> medium ->
            # easy so the scarce, discriminating cases are picked FIRST. The CSV
            # corpus is ~94% easy, so without this a sample is almost all-easy and
            # reports a flattering recall that hides hard-case failures (DCShadow,
            # kerberoast, ticket-without-$, ...). Stable sort preserves the prior
            # (deterministic) order within a difficulty band, so selection stays
            # reproducible. Difficulty read from GT (authoritative), then metadata.
            def _difficulty_rank(fi):
                name = fi.get('file_name') or Path(fi.get('full_path', '')).name
                gt_entry = self.ground_truth_data.get(name) or {}
                diff = (gt_entry.get('difficulty') or fi.get('difficulty') or 'easy').lower()
                return {'hard': 0, 'medium': 1, 'easy': 2}.get(diff, 2)
            for tid in tactic_files:
                tactic_files[tid] = sorted(tactic_files[tid], key=_difficulty_rank)
            benign_all = sorted(benign_all, key=_difficulty_rank)

            # Source-proportional benign picker: keep the reserved benign's mix of
            # source categories (evtx-baseline goodware vs folder_structure admin
            # near-misses) proportional to the corpus, so a sample's FP rate tracks
            # the full corpus instead of over-weighting the hard near-misses (which
            # front-load the iteration order and would inflate FP). Difficulty order
            # is preserved within each source group, so scarce hard benign still
            # come first. Largest-remainder apportionment.
            def _pick_benign(items, k):
                if k >= len(items):
                    return list(items)
                from collections import OrderedDict
                groups = OrderedDict()
                for it in items:
                    groups.setdefault(it.get('source', '?'), []).append(it)
                total = len(items)
                quota, remainder, assigned = {}, {}, 0
                for src, g in groups.items():
                    exact = k * len(g) / total
                    quota[src] = int(exact)
                    remainder[src] = exact - quota[src]
                    assigned += quota[src]
                for src in sorted(remainder, key=lambda s: remainder[s], reverse=True):
                    if assigned >= k:
                        break
                    quota[src] += 1
                    assigned += 1
                picked = []
                for src, g in groups.items():
                    picked.extend(g[:quota[src]])
                return picked

            if self.include_benign and benign_all:
                attack_available = sum(len(v) for v in tactic_files.values())
                # Verdict-grade sample: split the budget ~EVENLY between the two
                # classes so BOTH scale as the sample grows and recall/FP are
                # estimated with similar precision. The old rule pinned attacks at
                # MIN+5 and poured every extra file into benign, so a bigger
                # sample_size only ever grew the benign side (the "thin attack axis"
                # that made Standard a weak verdict). Each half is floored at the
                # verdict minimum and capped by what's available; if one class is
                # scarce the other takes the slack.
                if (max_files >= 2 * MIN_SAMPLES_FOR_VERDICT
                        and len(benign_all) >= MIN_SAMPLES_FOR_VERDICT
                        and attack_available >= MIN_SAMPLES_FOR_VERDICT):
                    half = max_files // 2
                    benign_cap = min(len(benign_all), max(MIN_SAMPLES_FOR_VERDICT, half))
                    # If attacks can't fill their share, hand the slack to benign.
                    if max_files - benign_cap > attack_available:
                        benign_cap = min(len(benign_all), max_files - attack_available)
                    reserved_benign = _pick_benign(benign_all, benign_cap)
                    if benign_cap < len(benign_all):
                        print(f"{Fore.CYAN}[INFO] Balanced verdict sample: "
                              f"{benign_cap} benign + up to {max_files - benign_cap} attack "
                              f"(>= {MIN_SAMPLES_FOR_VERDICT} of each)."
                              f"{Style.RESET_ALL}")
                else:
                    # Small / edge sample (e.g. Smoke): the run isn't verdict-capable,
                    # so cap the benign reservation to keep Smoke a *fast* pipeline
                    # check. Before the 2026-06-12 all-real reset the benign set was 41
                    # and this reserved all of them (harmless); at 90 it bloated Smoke to
                    # ~91 files. Cap keeps Smoke ~16 (15 benign + >=1 attack).
                    SMOKE_BENIGN_CAP = 15
                    reserved_benign = benign_all[:SMOKE_BENIGN_CAP]
                    if len(reserved_benign) > max_files:
                        print(f"{Fore.YELLOW}[INFO] include_benign reserved "
                              f"{len(reserved_benign)} benign files; expanding "
                              f"effective sample size from {max_files} to "
                              f"{len(reserved_benign) + max(1, max_files - len(reserved_benign))} "
                              f"to keep at least 1 attack file in scope."
                              f"{Style.RESET_ALL}")

            num_tactics = max(1, len(tactic_files))
            # Budget for ATTACK files: at least 1 if any attacks are
            # available, otherwise whatever's left after the benign reservation.
            remaining_budget = max(0, max_files - len(reserved_benign))
            if remaining_budget == 0 and tactic_files and self.include_benign:
                # Sample size was fully consumed by benigns. Bump by 1 so
                # the run isn't 100% benign — that defeats both the recall
                # and FP-rate measurements.
                remaining_budget = 1
            per_tactic = max(1, remaining_budget // num_tactics) if remaining_budget else 0

            sample_files = list(reserved_benign)
            for tactic_id, tactic_list in tactic_files.items():
                sample_files.extend(tactic_list[:per_tactic])

            # Round-robin fill: cycle through tactics adding one at a time
            attack_target = len(reserved_benign) + remaining_budget
            if len(sample_files) < attack_target:
                remaining = {tid: tlist[per_tactic:] for tid, tlist in tactic_files.items()
                             if len(tlist) > per_tactic}
                while len(sample_files) < attack_target and remaining:
                    for tid in sorted(remaining, key=lambda t: len(remaining[t]), reverse=True):
                        if len(sample_files) >= attack_target:
                            break
                        if remaining[tid]:
                            sample_files.append(remaining[tid].pop(0))
                    remaining = {t: r for t, r in remaining.items() if r}

            # Final cap: keep all reserved benigns; trim only attack overflow.
            # `sample_files` was built benigns-first, so slice from the end
            # only if we exceeded the target.
            return sample_files[:attack_target]

        elif choice == '3':
            # All files
            return list(files.values())

        return []

    def _prefilter_by_tags(self, files: Dict[str, Dict]) -> Dict[str, Dict]:
        """Filter the candidate pool by difficulty/test_set before sampling.

        Selection is deterministic: the pool is metadata insertion order and
        the round-robin is sorted, so a given (corpus, filters, sample_size)
        always yields the same file list. There is no random seed.
        """
        if not self.difficulty and not self.test_set:
            return files

        kept: Dict[str, Dict] = {}
        for filename, fi in files.items():
            if self.difficulty and self._lookup_file_tag(filename, 'difficulty') != self.difficulty:
                continue
            if self.test_set and self._lookup_file_tag(filename, 'test_set') != self.test_set:
                continue
            kept[filename] = fi

        if not kept:
            print(f"{Fore.YELLOW}[WARN] No files match the specified filters "
                  f"(difficulty={self.difficulty}, test_set={self.test_set}){Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[OK] Filtered pool to {len(kept)} files "
                  f"(difficulty={self.difficulty or 'any'}, test_set={self.test_set or 'any'}){Style.RESET_ALL}")
        return kept

