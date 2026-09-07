export interface ImpactAiSettings {
  enabled: boolean;
  base_url: string;
  model: string;
  api_key_set: boolean;
  api_key_last_four: string | null;
}

export interface ImpactAiSettingsUpdate {
  enabled: boolean;
  base_url: string;
  model: string;
  api_key: string | null;
  clear_api_key: boolean;
}
