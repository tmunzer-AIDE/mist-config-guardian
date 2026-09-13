"""Celery application for background work."""

from celery import Celery

from mist_config_guardian_backend.config import get_settings

settings = get_settings()

celery_app = Celery(
    "mist_config_guardian",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=[
        "mist_config_guardian_backend.tasks.snapshots",
        "mist_config_guardian_backend.tasks.webhooks",
        "mist_config_guardian_backend.tasks.restores",
        "mist_config_guardian_backend.tasks.monitoring",
        "mist_config_guardian_backend.tasks.change_groups",
        "mist_config_guardian_backend.tasks.hashes",
        "mist_config_guardian_backend.tasks.investigation_retention",
    ],
)
celery_app.conf.update(
    enable_utc=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    timezone="UTC",
    beat_schedule={
        "impact-retention": {"task": "impact.maintain_retention", "schedule": 3600.0},
        "poll-active-monitoring": {
            "task": "monitoring.poll_active",
            "schedule": 60.0,
        },
        "expire-restore-credentials": {
            "task": "restores.expire_credentials",
            "schedule": 60.0,
        },
        "expire-restore-approvals": {
            "task": "restores.expire_approvals",
            "schedule": 300.0,
        },
        # Change groups recorded before the projection existed, and any whose
        # rebuild was lost to a worker restart, are filled in here.
        "backfill-change-group-projections": {
            "task": "change_groups.backfill_projections",
            "schedule": 900.0,
        },
        # Configuration digests written before the hash was keyed are rewritten
        # here. Comparison already tolerates both, so this only decides how long
        # the unkeyed ones linger; it empties and then does nothing.
        "backfill-configuration-hashes": {
            "task": "hashes.backfill_configuration_hashes",
            "schedule": 900.0,
        },
    },
)
