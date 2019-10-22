package encryption

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/coreos/etcd/clientv3"
	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	apiserverconfigv1 "k8s.io/apiserver/pkg/apis/config/v1"
	"k8s.io/client-go/kubernetes"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/cluster-kube-apiserver-operator/pkg/operator/operatorclient"
)

var protoEncodingPrefix = []byte{0x6b, 0x38, 0x73, 0x00}

var defaultTargetGRs = []schema.GroupResource{
	{Group: "", Resource: "secrets"},
	{Group: "", Resource: "configmaps"},
}

const (
	jsonEncodingPrefix           = "{"
	protoEncryptedDataPrefix     = "k8s:enc:"
	aesCBCTransformerPrefixV1    = "k8s:enc:aescbc:v1:"
	secretboxTransformerPrefixV1 = "k8s:enc:secretbox:v1:"
)

var (
	apiserverScheme = runtime.NewScheme()
	apiserverCodecs = serializer.NewCodecFactory(apiserverScheme)
)

func init() {
	utilruntime.Must(apiserverconfigv1.AddToScheme(apiserverScheme))
}

func AssertSecretsAndConfigMaps(t testing.TB, clientSet ClientSet, expectedMode configv1.EncryptionType) {
	t.Helper()
	assertSecrets(t, clientSet.Etcd, string(expectedMode))
	assertConfigMaps(t, clientSet.Etcd, string(expectedMode))
	assertLastMigratedKey(t, clientSet.Kube)
}

func AssertSecretOfLifeNotEncrypted(t testing.TB, clientSet ClientSet, secretOfLife *corev1.Secret) {
	t.Helper()
	rawSecretValue := GetRawSecretOfLife(t, clientSet)
	if !strings.Contains(rawSecretValue, string(secretOfLife.Data["quote"])) {
		t.Errorf("The secret received from etcd doesn't have %q, content of the secret (etcd) %s", string(secretOfLife.Data["quote"]), rawSecretValue)
	}
}

func AssertSecretOfLifeEncrypted(t testing.TB, clientSet ClientSet, secretOfLife *corev1.Secret) {
	t.Helper()
	rawSecretValue := GetRawSecretOfLife(t, clientSet)
	if strings.Contains(rawSecretValue, string(secretOfLife.Data["quote"])) {
		t.Errorf("The secret received from etcd have %q (plain text), content of the secret (etcd) %s", string(secretOfLife.Data["quote"]), rawSecretValue)
	}
}

func AssertEncryptionConfigForSecretsAndConfigMaps(t testing.TB, clientSet ClientSet) {
	t.Helper()
	t.Logf("Checking if %q in %q has desired GRs %v", "encryption-config-openshift-kube-apiserver", operatorclient.GlobalMachineSpecifiedConfigNamespace, defaultTargetGRs)
	encryptionCofnigSecret, err := clientSet.Kube.CoreV1().Secrets(operatorclient.GlobalMachineSpecifiedConfigNamespace).Get("encryption-config-openshift-kube-apiserver", metav1.GetOptions{})
	require.NoError(t, err)
	encodedEncryptionConfig, foundEncryptionConfig := encryptionCofnigSecret.Data["encryption-config"]
	if !foundEncryptionConfig {
		t.Errorf("Haven't found encryption config at %q key in the encryption secret %q", "encryption-config", "encryption-config-openshift-kube-apiserver")
	}

	decoder := apiserverCodecs.UniversalDecoder(apiserverconfigv1.SchemeGroupVersion)
	encryptionConfigObj, err := runtime.Decode(decoder, encodedEncryptionConfig)
	require.NoError(t, err)
	encryptionConfig, ok := encryptionConfigObj.(*apiserverconfigv1.EncryptionConfiguration)
	if !ok {
		t.Errorf("Unable to decode encryption config, unexpected wrong type %T", encryptionConfigObj)
	}

	for _, rawActualResource := range encryptionConfig.Resources {
		if len(rawActualResource.Resources) != 1 {
			t.Errorf("Invalid encryption config for resource %s, expected exactly one resource, got %d", rawActualResource.Resources, len(rawActualResource.Resources))
		}
		actualResource := schema.ParseGroupResource(rawActualResource.Resources[0])
		actualResourceFound := false
		for _, expectedResource := range defaultTargetGRs {
			if reflect.DeepEqual(expectedResource, actualResource) {
				actualResourceFound = true
				break
			}
		}
		if !actualResourceFound {
			t.Errorf("Encryption config has an invalid resource %v", actualResource)
		}
	}
}

func assertSecrets(t testing.TB, etcdClient EtcdClient, expectedMode string) {
	t.Logf("Checking if all Secrets where encrypted/decrypted for %q mode", expectedMode)
	totalSecrets, err := verifyResources(t, etcdClient, "/kubernetes.io/secrets/", expectedMode)
	t.Logf("Verified %d Secrets, err %v", totalSecrets, err)
	require.NoError(t, err)
}

func assertConfigMaps(t testing.TB, etcdClient EtcdClient, expectedMode string) {
	t.Logf("Checking if all ConfigMaps where encrypted/decrypted for %q mode", expectedMode)
	totalConfigMaps, err := verifyResources(t, etcdClient, "/kubernetes.io/configmaps/", expectedMode)
	t.Logf("Verified %d ConfigMaps, err %v", totalConfigMaps, err)
	require.NoError(t, err)
}

func assertLastMigratedKey(t testing.TB, kubeClient kubernetes.Interface) {
	t.Helper()
	expectedGRs := defaultTargetGRs
	t.Logf("Checking if the last migrated key was used to encrypt %v", expectedGRs)
	lastMigratedKeyMeta, err := GetLastKeyMeta(kubeClient)
	require.NoError(t, err)
	if len(lastMigratedKeyMeta.Name) == 0 {
		t.Log("Nothing to check no new key was created")
		return
	}

	if len(expectedGRs) != len(lastMigratedKeyMeta.Migrated) {
		t.Errorf("Wrong number of migrated resources for %q key, expected %d, got %d", lastMigratedKeyMeta.Name, len(expectedGRs), len(lastMigratedKeyMeta.Migrated))
	}

	for _, expectedGR := range expectedGRs {
		if !hasResource(expectedGR, lastMigratedKeyMeta.Migrated) {
			t.Errorf("%q wasn't used to encrypt %v, only %v", lastMigratedKeyMeta.Name, expectedGR, lastMigratedKeyMeta.Migrated)
		}
	}
}

func verifyResources(t testing.TB, etcdClient EtcdClient, etcdKeyPreifx, expectedMode string) (int, error) {
	timeout, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	resp, err := etcdClient.Get(timeout, etcdKeyPreifx, clientv3.WithPrefix())
	switch {
	case err != nil:
		return 0, fmt.Errorf("failed to list prefix %s: %v", etcdKeyPreifx, err)
	case resp.Count == 0 || len(resp.Kvs) == 0:
		return 0, fmt.Errorf("empty list response for prefix %s: %+v", etcdKeyPreifx, resp)
	case resp.More:
		return 0, fmt.Errorf("incomplete list response for prefix %s: %+v", etcdKeyPreifx, resp)
	}

	for _, keyValue := range resp.Kvs {
		if err := verifyPrefixForRawData(expectedMode, keyValue.Value); err != nil {
			return 0, fmt.Errorf("key %s failed check: %v\n%s", keyValue.Key, err, hex.Dump(keyValue.Value))
		}
	}

	return len(resp.Kvs), nil
}

func verifyPrefixForRawData(expectedMode string, data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data")
	}

	conditionToStr := func(condition bool) string {
		if condition {
			return "encrypted"
		}
		return "unencrypted"
	}

	expectedEncrypted := true
	if expectedMode == "identity" {
		expectedMode = "identity-proto"
		expectedEncrypted = false
	}

	actualMode, isEncrypted := encryptionModeFromEtcdValue(data)
	if expectedEncrypted != isEncrypted {
		return fmt.Errorf("unexpected encrypted state, expected data to be %q but was %q with mode %q", conditionToStr(expectedEncrypted), conditionToStr(isEncrypted), actualMode)
	}
	if actualMode != expectedMode {
		return fmt.Errorf("unexpected encryption mode %q, expected %q, was data encrypted/decrypted with a wrong key", actualMode, expectedMode)
	}

	return nil
}

func encryptionModeFromEtcdValue(data []byte) (string, bool) {
	isEncrypted := bytes.HasPrefix(data, []byte(protoEncryptedDataPrefix)) // all encrypted data has this prefix
	return func() string {
		switch {
		case hasPrefixAndTrailingData(data, []byte(aesCBCTransformerPrefixV1)): // AES-CBC has this prefix
			return "aescbc"
		case hasPrefixAndTrailingData(data, []byte(secretboxTransformerPrefixV1)): // Secretbox has this prefix
			return "secretbox"
		case hasPrefixAndTrailingData(data, []byte(jsonEncodingPrefix)): // unencrypted json data has this prefix
			return "identity-json"
		case hasPrefixAndTrailingData(data, protoEncodingPrefix): // unencrypted protobuf data has this prefix
			return "identity-proto"
		default:
			return "unknown" // this should never happen
		}
	}(), isEncrypted
}

func hasPrefixAndTrailingData(data, prefix []byte) bool {
	return bytes.HasPrefix(data, prefix) && len(data) > len(prefix)
}
