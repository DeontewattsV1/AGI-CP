name: Reusable Full History Secret Audit

on:
  workflow_call:

permissions:
  contents: read
  actions: read
  issues: read
  pull-requests: read

jobs:
  audit:
    name: all-refs / history / external surfaces
    runs-on: ubuntu-latest
    timeout-minutes: 180
    env:
      GH_TOKEN: ${{ github.token }}
      GITLEAKS_IMAGE: ghcr.io/gitleaks/gitleaks:v8.30.1
    steps:
      - name: Checkout repository
        uses: actions/checkout@v6
        with:
          fetch-depth: 0
          persist-credentials: true

      - name: Fetch all advertised refs and LFS objects
        shell: bash
        run: |
          set -euo pipefail
          git fetch --force --prune origin '+refs/*:refs/audit/*'
          git lfs install --local >/dev/null 2>&1 || true
          git lfs fetch --all || true
          mkdir -p .audit/raw .audit/safe .audit/external/{release-assets,actions-artifacts,actions-logs,attachments,metadata}

      - name: Collect release assets, Actions artifacts/logs, issues, PRs and attachments
        id: collect
        shell: bash
        run: |
          set -u
          errors=0
          inaccessible=0
          root="$PWD/.audit/external"

          collect_json() {
            local endpoint="$1" out="$2"
            if ! gh api --paginate --slurp "$endpoint" > "$out" 2>/dev/null; then
              echo '[]' > "$out"
              errors=$((errors + 1))
            fi
          }

          collect_json "repos/${GITHUB_REPOSITORY}/releases?per_page=100" "$root/metadata/releases.json"
          collect_json "repos/${GITHUB_REPOSITORY}/actions/artifacts?per_page=100" "$root/metadata/artifacts.json"
          collect_json "repos/${GITHUB_REPOSITORY}/actions/runs?per_page=100" "$root/metadata/runs.json"
          collect_json "repos/${GITHUB_REPOSITORY}/issues?state=all&per_page=100" "$root/metadata/issues.json"
          collect_json "repos/${GITHUB_REPOSITORY}/issues/comments?per_page=100" "$root/metadata/issue-comments.json"
          collect_json "repos/${GITHUB_REPOSITORY}/pulls/comments?per_page=100" "$root/metadata/pr-review-comments.json"

          while IFS=$'\t' read -r id name url; do
            [ -n "${id:-}" ] || continue
            safe_name=$(printf '%s' "$name" | tr '/\\ ' '___' | tr -cd '[:alnum:]_.-')
            if ! curl -fsSL -H "Authorization: Bearer $GH_TOKEN" -H "Accept: application/octet-stream" "$url" -o "$root/release-assets/${id}-${safe_name}"; then
              inaccessible=$((inaccessible + 1))
            fi
          done < <(jq -r '.[] | .[]? | .assets[]? | [.id,.name,.url] | @tsv' "$root/metadata/releases.json" 2>/dev/null)

          expired_artifacts=$(jq '[.[] | .artifacts[]? | select(.expired == true)] | length' "$root/metadata/artifacts.json" 2>/dev/null || echo 0)
          inaccessible=$((inaccessible + expired_artifacts))
          while IFS=$'\t' read -r id name; do
            [ -n "${id:-}" ] || continue
            safe_name=$(printf '%s' "$name" | tr '/\\ ' '___' | tr -cd '[:alnum:]_.-')
            if ! curl -fsSL -L -H "Authorization: Bearer $GH_TOKEN" -H "Accept: application/vnd.github+json" "https://api.github.com/repos/${GITHUB_REPOSITORY}/actions/artifacts/${id}/zip" -o "$root/actions-artifacts/${id}-${safe_name}.zip"; then
              inaccessible=$((inaccessible + 1))
            fi
          done < <(jq -r '.[] | .artifacts[]? | select(.expired == false) | [.id,.name] | @tsv' "$root/metadata/artifacts.json" 2>/dev/null)

          while read -r run_id; do
            [ -n "${run_id:-}" ] || continue
            [ "$run_id" = "$GITHUB_RUN_ID" ] && continue
            if ! curl -fsSL -L -H "Authorization: Bearer $GH_TOKEN" -H "Accept: application/vnd.github+json" "https://api.github.com/repos/${GITHUB_REPOSITORY}/actions/runs/${run_id}/logs" -o "$root/actions-logs/${run_id}.zip"; then
              inaccessible=$((inaccessible + 1))
              rm -f "$root/actions-logs/${run_id}.zip"
            fi
          done < <(jq -r '.[] | .workflow_runs[]? | .id' "$root/metadata/runs.json" 2>/dev/null)

          grep -RhoE 'https://(private-user-images\.githubusercontent\.com|user-images\.githubusercontent\.com|github\.com/user-attachments/assets)/[^"[:space:]]+' "$root/metadata" 2>/dev/null | sort -u > "$root/metadata/attachment-urls.txt" || true
          n=0
          while IFS= read -r url; do
            [ -n "$url" ] || continue
            n=$((n + 1))
            if ! curl -fsSL -L -H "Authorization: Bearer $GH_TOKEN" "$url" -o "$root/attachments/attachment-${n}"; then
              inaccessible=$((inaccessible + 1))
              rm -f "$root/attachments/attachment-${n}"
            fi
          done < "$root/metadata/attachment-urls.txt"

          echo "collection_errors=$errors" >> "$GITHUB_OUTPUT"
          echo "inaccessible_objects=$inaccessible" >> "$GITHUB_OUTPUT"

      - name: Scan all Git history, LFS objects, and collected external surfaces
        id: scan
        shell: bash
        run: |
          set +e
          history_code=0
          lfs_code=0
          external_code=0

          docker run --rm -v "$PWD:/repo" -w /repo "$GITLEAKS_IMAGE" detect \
            --source=/repo --log-opts='--all' --redact \
            --max-archive-depth=3 --max-decode-depth=2 \
            --report-format=json --report-path=/repo/.audit/raw/history.json
          history_code=$?

          if [ -d .git/lfs/objects ] && [ -n "$(find .git/lfs/objects -type f -print -quit 2>/dev/null)" ]; then
            docker run --rm -v "$PWD:/repo" -w /repo "$GITLEAKS_IMAGE" detect \
              --no-git --source=/repo/.git/lfs/objects --redact \
              --max-archive-depth=3 --max-decode-depth=2 \
              --report-format=json --report-path=/repo/.audit/raw/lfs.json
            lfs_code=$?
          else
            echo '[]' > .audit/raw/lfs.json
          fi

          docker run --rm -v "$PWD:/repo" -w /repo "$GITLEAKS_IMAGE" detect \
            --no-git --source=/repo/.audit/external --redact \
            --max-archive-depth=3 --max-decode-depth=2 \
            --report-format=json --report-path=/repo/.audit/raw/external.json
          external_code=$?

          sanitize() {
            local src="$1" dst="$2"
            if [ -s "$src" ]; then
              jq '[.[] | {RuleID,Description,File,Commit,StartLine,EndLine,Fingerprint}]' "$src" > "$dst" 2>/dev/null || echo '[]' > "$dst"
            else
              echo '[]' > "$dst"
            fi
          }
          sanitize .audit/raw/history.json .audit/safe/history-findings.json
          sanitize .audit/raw/lfs.json .audit/safe/lfs-findings.json
          sanitize .audit/raw/external.json .audit/safe/external-findings.json

          history_count=$(jq 'length' .audit/safe/history-findings.json)
          lfs_count=$(jq 'length' .audit/safe/lfs-findings.json)
          external_count=$(jq 'length' .audit/safe/external-findings.json)
          total=$((history_count + lfs_count + external_count))
          rm -rf .audit/raw .audit/external

          echo "history_code=$history_code" >> "$GITHUB_OUTPUT"
          echo "lfs_code=$lfs_code" >> "$GITHUB_OUTPUT"
          echo "external_code=$external_code" >> "$GITHUB_OUTPUT"
          echo "history_count=$history_count" >> "$GITHUB_OUTPUT"
          echo "lfs_count=$lfs_count" >> "$GITHUB_OUTPUT"
          echo "external_count=$external_count" >> "$GITHUB_OUTPUT"
          echo "total=$total" >> "$GITHUB_OUTPUT"
          exit 0

      - name: Build publication-gate status
        id: gate
        shell: bash
        run: |
          set -euo pipefail
          findings='${{ steps.scan.outputs.total }}'
          errors='${{ steps.collect.outputs.collection_errors }}'
          inaccessible='${{ steps.collect.outputs.inaccessible_objects }}'
          scan_error=0
          for code in '${{ steps.scan.outputs.history_code }}' '${{ steps.scan.outputs.lfs_code }}' '${{ steps.scan.outputs.external_code }}'; do
            if [ "$code" -gt 1 ]; then scan_error=1; fi
          done
          status=PASS
          if [ "$findings" -gt 0 ]; then status=FAIL_FINDINGS; fi
          if [ "$errors" -gt 0 ] || [ "$scan_error" -gt 0 ] || [ "$inaccessible" -gt 0 ]; then status=INCOMPLETE; fi

          cat > .audit/safe/status.json <<EOF
          {
            "repository": "${GITHUB_REPOSITORY}",
            "run_id": "${GITHUB_RUN_ID}",
            "gitleaks": "v8.30.1",
            "scope": ["all-advertised-refs", "git-history", "tags", "secondary-branches", "lfs-objects", "release-assets", "actions-artifacts", "actions-logs", "issues-pr-metadata", "issues-pr-attachments"],
            "history_findings": ${{ steps.scan.outputs.history_count }},
            "lfs_findings": ${{ steps.scan.outputs.lfs_count }},
            "external_findings": ${{ steps.scan.outputs.external_count }},
            "collection_errors": $errors,
            "inaccessible_objects": $inaccessible,
            "status": "$status"
          }
          EOF

          {
            echo "## Full History Secret Audit"
            echo ""
            echo "- Status: **$status**"
            echo "- Git-history findings: ${{ steps.scan.outputs.history_count }}"
            echo "- LFS findings: ${{ steps.scan.outputs.lfs_count }}"
            echo "- External-surface findings: ${{ steps.scan.outputs.external_count }}"
            echo "- Collection errors: $errors"
            echo "- Inaccessible/expired objects: $inaccessible"
            echo ""
            echo "A PASS is a publication gate for secret exposure only; it is not a general security certification."
          } | tee .audit/safe/summary.md >> "$GITHUB_STEP_SUMMARY"
          echo "status=$status" >> "$GITHUB_OUTPUT"

      - name: Upload redacted audit evidence
        if: always()
        uses: actions/upload-artifact@v7
        with:
          name: full-history-secret-audit-${{ github.run_id }}
          path: .audit/safe/
          if-no-files-found: error
          retention-days: 30

      - name: Enforce publication gate
        shell: bash
        run: |
          case '${{ steps.gate.outputs.status }}' in
            PASS) exit 0 ;;
            FAIL_FINDINGS) echo 'Secret findings detected. Repository must remain private until remediated.'; exit 1 ;;
            *) echo 'Audit incomplete because some surfaces could not be scanned. Repository must remain private.'; exit 2 ;;
          esac
