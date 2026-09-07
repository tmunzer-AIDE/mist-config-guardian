export type RestoreMode = 'exact' | 'non_destructive';
export type RestoreStatus =
  | 'planned'
  | 'queued'
  | 'running'
  | 'completed'
  | 'failed'
  | 'compensation_available'
  | 'compensated';

export interface RestoreAction {
  logical_object_id: string;
  source_version_id: string;
  order: number;
  action: 'create' | 'update' | 'delete';
  scope: string;
  object_type: string;
  object_name: string;
  current_mist_id: string;
  site_mist_id: string | null;
  configuration: Record<string, unknown>;
  depends_on: string[];
  status: 'pending' | 'executing' | 'completed' | 'failed' | 'skipped';
  resulting_mist_id: string | null;
  error: string | null;
}

export interface RestoreOperation {
  id: string;
  mode: RestoreMode;
  include_dependencies: boolean;
  target_at: string;
  status: RestoreStatus;
  actions: RestoreAction[];
  warnings: string[];
  preflight_errors: string[];
  credential_actor: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  task_id: string | null;
}
