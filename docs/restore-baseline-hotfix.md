# Fresh backup before restore — 12 September 2026

The restore workflow now captures the selected objects and dependencies using a freshly verified administrator identity, creates immutable object versions in a manual snapshot, and returns a new planned restore. The new plan uses those exact captured versions as its baseline, even if a background service-token backup runs afterwards. It does not inherit the previous plan's approval.

The reviewer can compare each captured version with its target from the plan table. Execution uses the same encrypted, short-lived credential. Only the administrator who prepared the plan can use that retained credential; queue reservation is atomic and does not extend its expiry. Expiry cleanup also revokes sessions waiting for review. Execution still reads live state and refuses drift before making any configuration writes.

If live object existence differs from recorded history, preparation requires a history refresh instead of silently changing create/delete behavior. If the administrator response contains an unavailable secret, preparation refuses to call it a recoverable backup. `root_password` is now included in field encryption and secret preflight checks. Failed capture may leave a failed snapshot with successfully captured immutable versions, but does not queue a restore.

## Deployment

An isolated build based on the deployed source plus these changes is installed in namespace `mist`. Unrelated workspace login/MFA edits were excluded.

- Backend ConfigMap: `guardian-fresh-baseline-20260912`.
- Frontend ConfigMaps: `guardian-fresh-baseline-20260912-web-0` through `-web-2`, plus `guardian-fresh-baseline-20260912-review` for the final comparison-link bundles.
- API, worker, scheduler, and frontend use read-only ConfigMap subPath mounts.
- Previous restore-debug overlays remain installed.

This is a temporary source/bundle overlay, not a published container release. Remove the mounts when deploying an image containing the permanent change; otherwise the mounted modules continue to override the image. Deployment manifests and before-state are in `/tmp/guardian-fresh-baseline/deployment` on this workstation.

## Rollback

The prepared strategic-merge patches remove only this change's mounts and volumes. They preserve the earlier debug overlay and unrelated deployment settings. Run the frontend rollback first, then API, worker, and scheduler:

```sh
kubectl -n mist patch deploy config-guardian-mist-config-guardian-frontend --type=strategic --patch-file=/tmp/guardian-fresh-baseline/deployment/frontend-rollback.json
kubectl -n mist patch deploy config-guardian-mist-config-guardian-api --type=strategic --patch-file=/tmp/guardian-fresh-baseline/deployment/api-rollback.json
kubectl -n mist patch deploy config-guardian-mist-config-guardian-worker --type=strategic --patch-file=/tmp/guardian-fresh-baseline/deployment/worker-rollback.json
kubectl -n mist patch deploy config-guardian-mist-config-guardian-scheduler --type=strategic --patch-file=/tmp/guardian-fresh-baseline/deployment/scheduler-rollback.json
```

Allow any running restore to finish before rollback. Review sessions created by this change should expire and be revoked by the updated worker before removing its credential-cleanup support.
