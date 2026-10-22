-- name: LiveSubscriptionByUser :one
SELECT s.id AS subscription_id, s.user_id, s.status, s.starts_at, s.ends_at, s.source,
       p.id AS plan_id, p.slug, p.device_limit, p.server_selector,
       p.traffic_quota_bytes, p.trial_days
FROM subscriptions s
JOIN subscription_plans p ON p.id = s.plan_id
WHERE s.user_id = $1 AND s.status = 'active'
  AND (s.ends_at IS NULL OR s.ends_at > now())
ORDER BY s.starts_at DESC
LIMIT 1;

-- name: PlanBySlug :one
SELECT id, slug, device_limit, server_selector, traffic_quota_bytes, trial_days
FROM subscription_plans WHERE slug = $1;

-- name: InsertSubscription :one
INSERT INTO subscriptions (id, user_id, plan_id, status, starts_at, ends_at, source)
VALUES ($1, $2, $3, 'active', $4, $5, 'manual')
RETURNING id;
