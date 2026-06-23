SELECT remove_retention_policy('quiver.system_metrics', if_exists => TRUE);
DROP TABLE IF EXISTS quiver.system_metrics CASCADE;
