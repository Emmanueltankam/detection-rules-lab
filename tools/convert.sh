#!/usr/bin/env bash
# Convert every Sigma rule into ready-to-use SIEM queries:
#   dist/splunk/<rule>.spl      Splunk SPL
#   dist/elastic/<rule>.lucene  Elastic / Kibana (Lucene, ECS field names for Windows)
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="${1:-dist}"
rm -rf "$OUT"
mkdir -p "$OUT/splunk" "$OUT/elastic"

count=0
while IFS= read -r -d '' rule; do
  name="$(basename "$rule" .yml)"
  if [[ "$rule" == rules/windows/* ]]; then
    splunk_args=(-p splunk_windows)
    elastic_args=(-p ecs_windows)
  else
    splunk_args=(--without-pipeline)
    elastic_args=(--without-pipeline)
  fi
  sigma convert -t splunk "${splunk_args[@]}" "$rule" -o "$OUT/splunk/$name.spl" > /dev/null
  sigma convert -t lucene "${elastic_args[@]}" "$rule" -o "$OUT/elastic/$name.lucene" > /dev/null
  count=$((count + 1))
done < <(find rules -name '*.yml' -print0 | sort -z)

echo "Converted $count rules into $OUT/splunk and $OUT/elastic"
