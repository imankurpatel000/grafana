package encryption

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/server"
	"github.com/grafana/grafana/pkg/services/apiserver/options"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/ngalert/notifier"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgimpl"
	"github.com/grafana/grafana/pkg/services/quota/quotaimpl"
	"github.com/grafana/grafana/pkg/services/supportbundles/supportbundlestest"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/userimpl"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/tests/testinfra"
	"github.com/grafana/grafana/pkg/tests/testsuite"
)

func TestMain(m *testing.M) {
	testsuite.Run(m)
}

func TestAdminApiReencrypt(t *testing.T) {
	dir, path := testinfra.CreateGrafDir(t, testinfra.GrafanaOpts{
		//EnableLog: true,
		APIServerStorageType: options.StorageTypeUnified,
		//EnableFeatureToggles: []string{featuremgmt.FlagAppPlatformGrpcClientAuth},
	})

	grafanaListenAddr, env := testinfra.StartGrafanaEnv(t, dir, path)
	userId := createUser(t, env.SQLStore, env.Cfg, user.CreateUserCommand{
		DefaultOrgRole: string(org.RoleAdmin),
		Password:       "admin",
		Login:          "admin",
	})

	const key = "db-secure-key"
	dsCmd := &datasources.AddDataSourceCommand{
		Name:            "TestDatasource",
		Type:            "testdata",
		Access:          datasources.DS_ACCESS_DIRECT,
		UID:             "testuid",
		UserID:          userId,
		OrgID:           1,
		WithCredentials: true,
		SecureJsonData: map[string]string{
			key: "db-secure-value",
		},
	}
	// This creates secret both in `data_source` table and `secrets` table.
	_, err := env.Server.HTTPServer.DataSourcesService.AddDataSource(context.Background(), dsCmd)
	require.NoError(t, err)

	// Add alerting config with secure settings
	addAlertingConfig(t, grafanaListenAddr, env)

	const (
		dataSourceTable              = "data_source"
		secretsTable                 = "secrets"
		secretsValueColumn           = "value"
		alertmanagerSecureSettingKey = "secure-value"
	)

	jsonSecretsBeforeReencrypt := getSecureJsonSecrets(t, env.SQLStore, dataSourceTable, key)
	base64SecretsBeforeReencrypt := getBase64Secrets(t, env.SQLStore, secretsTable, secretsValueColumn, base64.RawStdEncoding)
	alertmanagerSecretsBeforeReencrypt := getAlertmanagerSecrets(t, env.SQLStore, alertmanagerSecureSettingKey)

	ok, err := env.Server.HTTPServer.SecretsMigrator.ReEncryptSecrets(context.Background())
	require.NoError(t, err)
	assert.True(t, ok, "Failed to reencrypt all secrets")

	jsonSecretsAfterReencrypt := getSecureJsonSecrets(t, env.SQLStore, dataSourceTable, key)
	base64SecretsAfterReencrypt := getBase64Secrets(t, env.SQLStore, secretsTable, secretsValueColumn, base64.RawStdEncoding)
	alertmanagerSecretsAfterReencrypt := getAlertmanagerSecrets(t, env.SQLStore, alertmanagerSecureSettingKey)

	verifySecrets(t, env, jsonSecretsBeforeReencrypt, jsonSecretsAfterReencrypt)
	verifySecrets(t, env, base64SecretsBeforeReencrypt, base64SecretsAfterReencrypt)
	verifySecrets(t, env, alertmanagerSecretsBeforeReencrypt, alertmanagerSecretsAfterReencrypt)

	ok, err = env.Server.HTTPServer.SecretsMigrator.RollBackSecrets(context.Background())
	require.NoError(t, err)
	assert.True(t, ok, "Failed to rollback all secrets")

	jsonSecretsAfterRollback := getSecureJsonSecrets(t, env.SQLStore, dataSourceTable, key)
	base64SecretsAfterRollback := getBase64Secrets(t, env.SQLStore, secretsTable, secretsValueColumn, base64.RawStdEncoding)
	alertmanagerSecretsAfterRollback := getAlertmanagerSecrets(t, env.SQLStore, alertmanagerSecureSettingKey)

	verifySecrets(t, env, jsonSecretsAfterReencrypt, jsonSecretsAfterRollback)
	verifySecrets(t, env, base64SecretsAfterReencrypt, base64SecretsAfterRollback)
	verifySecrets(t, env, alertmanagerSecretsAfterReencrypt, alertmanagerSecretsAfterRollback)
}

func getAlertmanagerSecrets(t *testing.T, store db.DB, secureSettingKey string) map[int]secret {
	var rows []struct {
		Id                        int
		AlertmanagerConfiguration string
	}
	err := store.WithDbSession(t.Context(), func(sess *db.Session) error {
		return sess.Table("alert_configuration").Cols("id", "alertmanager_configuration").Find(&rows)
	})
	require.NoError(t, err)

	result := map[int]secret{}

next:
	for _, r := range rows {
		postableUserConfig, err := notifier.Load([]byte(r.AlertmanagerConfiguration))
		require.NoError(t, err)

		// Find first grafana-managed receiver config with secure settings with given key, and extract it.
		for _, receiver := range postableUserConfig.AlertmanagerConfig.Receivers {
			for _, gmr := range receiver.GrafanaManagedReceivers {
				v := gmr.SecureSettings[secureSettingKey]
				if v == "" {
					continue
				}

				decoded, err := base64.StdEncoding.DecodeString(v)
				require.NoError(t, err)
				result[r.Id] = secret{
					id:     r.Id,
					secret: decoded,
				}
				continue next
			}
		}
	}
	return result
}

func addAlertingConfig(t *testing.T, grafanaListenAddr string, env *server.TestEnv) {
	body := `
		{
			"alertmanager_config": {
				"route": {
					"receiver": "grafana-default-email"
				},
				"receivers": [{
					"name": "grafana-default-email",
					"grafana_managed_receiver_configs": [{
						"uid": "",
						"name": "email receiver",
						"type": "email",
						"isDefault": true,
						"settings": {
							"addresses": "<example@email.com>"
						},
						"secureSettings": {
							"secure-value": "secret"
						}
					}]
				}]
			}
		}
		`

	url := fmt.Sprintf("http://admin:admin@%s/api/alertmanager/grafana/config/api/v1/alerts", grafanaListenAddr)
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusAccepted, resp.StatusCode)
}

func verifySecrets(t *testing.T, env *server.TestEnv, before map[int]secret, after map[int]secret) {
	require.Equal(t, len(before), len(after))
	for k, bef := range before {
		aft, ok := after[k]
		require.True(t, ok, "key not found: %d", k)

		require.NotEmpty(t, bef.secret, "before secret is empty for key %d", k)
		require.NotEmpty(t, aft.secret, "after secret is empty for key %d", k)
		require.NotEqual(t, bef.secret, aft.secret, "secrets are equal after reencrypt for key %d", k)

		s1, err := env.Server.HTTPServer.SecretsService.Decrypt(context.Background(), bef.secret)
		require.NoError(t, err)
		s2, err := env.Server.HTTPServer.SecretsService.Decrypt(context.Background(), aft.secret)
		require.NoError(t, err)
		assert.Equal(t, string(s1), string(s2), "decrypted secrets are not equal for key %d", k)

		updatedDiff := aft.update.Sub(bef.update)
		// Since we're storing timestamps with seconds resolution, diff can be 0.
		require.True(t, 0 <= updatedDiff && updatedDiff <= time.Minute, "Updated time difference (%v) outside of allowed range for key %d", updatedDiff, k)
	}
}

func createUser(t *testing.T, db db.DB, cfg *setting.Cfg, cmd user.CreateUserCommand) int64 {
	cfg.AutoAssignOrg = true
	cfg.AutoAssignOrgId = 1

	quotaService := quotaimpl.ProvideService(db, cfg)
	orgService, err := orgimpl.ProvideService(db, cfg, quotaService)
	require.NoError(t, err)
	usrSvc, err := userimpl.ProvideService(
		db, orgService, cfg, nil, nil, tracing.InitializeTracerForTest(),
		quotaService, supportbundlestest.NewFakeBundleService(),
	)
	require.NoError(t, err)

	u, err := usrSvc.Create(context.Background(), &cmd)
	require.NoError(t, err)
	return u.ID
}

type secret struct {
	id     int
	secret []byte
	update time.Time
}

func getSecureJsonSecrets(t *testing.T, store db.DB, table string, secureJsonDataKey string) map[int]secret {
	var rows []struct {
		Id             int
		SecureJsonData map[string][]byte
		Updated        time.Time
	}

	err := store.WithDbSession(t.Context(), func(sess *db.Session) error {
		return sess.Table(table).Cols("id", "secure_json_data", "updated").Find(&rows)
	})
	require.NoError(t, err)

	result := map[int]secret{}
	for _, r := range rows {
		result[r.Id] = secret{
			id:     r.Id,
			secret: r.SecureJsonData[secureJsonDataKey],
			update: r.Updated,
		}
	}
	return result
}

func getBase64Secrets(t *testing.T, store db.DB, table, column string, enc *base64.Encoding) map[int]secret {
	var rows []struct {
		Id      int
		Secret  string
		Updated time.Time
	}

	err := store.WithDbSession(t.Context(), func(sess *db.Session) error {
		return sess.Table(table).Select(fmt.Sprintf("id, %s as secret, updated", column)).Find(&rows)
	})
	require.NoError(t, err)

	result := map[int]secret{}
	for _, r := range rows {
		d, err := enc.DecodeString(r.Secret)
		require.NoError(t, err)
		result[r.Id] = secret{
			id:     r.Id,
			secret: d,
			update: r.Updated,
		}
	}
	return result
}
