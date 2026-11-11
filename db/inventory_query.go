package db

import "strings"

// ListInventorySessions and ConnectionSessions both filter on a substring and
// both read sessions through the same effective-state projection. This file is
// the single definition of each so the two queries cannot drift apart.

// inventoryEffectiveColumns projects the session row plus the computed
// effective_state. Columns are listed explicitly (never SELECT *) so adding a
// column to session_inventory cannot silently shift the scan order of the
// queries that wrap this projection.
const inventoryEffectiveColumns = inventoryColumns + `,CASE WHEN state='connected' AND heartbeat_at+heartbeat_ttl_seconds*interval '1 second'<now() THEN 'stale' ELSE state END AS effective_state`

// likePattern escapes SQL LIKE metacharacters for a substring match. Callers
// pass the result as the parameter of `<column> ILIKE $n`.
func likePattern(q string) string {
	return "%" + strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_").Replace(q) + "%"
}
