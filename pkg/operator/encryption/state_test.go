package encryption

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apiserverconfigv1 "k8s.io/apiserver/pkg/apis/config/v1"
)

func TestEncryptionConfigToGroupResourceKeysRoundtrip(t *testing.T) {
	scenarios := []struct {
		name   string
		input  *apiserverconfigv1.EncryptionConfiguration
		output map[schema.GroupResource]groupResourceKeys
	}{
		// scenario 1
		{
			name: "single write key",
			input: func() *apiserverconfigv1.EncryptionConfiguration {
				keysRes := encryptionKeysResourceTuple{
					resource: "secrets",
					keys: []apiserverconfigv1.Key{
						{
							Name:   "34",
							Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc=",
						},
					},
				}
				ec := createEncryptionCfgWithWriteKey([]encryptionKeysResourceTuple{keysRes})
				return ec
			}(),
			output: map[schema.GroupResource]groupResourceKeys{
				{Group: "", Resource: "secrets"}: {
					writeKey: keyAndMode{
						key: apiserverconfigv1.Key{Name: "34", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, mode: "aescbc",
					},
				},
			},
		},

		// scenario 2
		{
			name: "multiple keys",
			input: func() *apiserverconfigv1.EncryptionConfiguration {
				keysRes := encryptionKeysResourceTuple{
					resource: "secrets",
					keys: []apiserverconfigv1.Key{
						{
							Name:   "34",
							Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc=",
						},
						{
							Name:   "33",
							Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc=",
						},
					},
				}
				ec := createEncryptionCfgWithWriteKey([]encryptionKeysResourceTuple{keysRes})
				return ec
			}(),
			output: map[schema.GroupResource]groupResourceKeys{
				{Group: "", Resource: "secrets"}: {
					writeKey: keyAndMode{
						key: apiserverconfigv1.Key{Name: "34", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, mode: "aescbc",
					},
					readKeys: []keyAndMode{
						{key: apiserverconfigv1.Key{Name: "33", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, mode: "aescbc"},
					},
				},
			},
		},

		// scenario 3
		{
			name: "single write key multiple resources",
			input: func() *apiserverconfigv1.EncryptionConfiguration {
				keysRes := []encryptionKeysResourceTuple{
					{
						resource: "secrets",
						keys: []apiserverconfigv1.Key{
							{
								Name:   "34",
								Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc=",
							},
						},
					},

					{
						resource: "configmaps",
						keys: []apiserverconfigv1.Key{
							{
								Name:   "34",
								Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc=",
							},
						},
					},
				}
				ec := createEncryptionCfgWithWriteKey(keysRes)
				return ec
			}(),
			output: map[schema.GroupResource]groupResourceKeys{
				{Group: "", Resource: "secrets"}: {
					writeKey: keyAndMode{
						key: apiserverconfigv1.Key{Name: "34", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, mode: "aescbc",
					},
				},
				{Group: "", Resource: "configmaps"}: {
					writeKey: keyAndMode{
						key: apiserverconfigv1.Key{Name: "34", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, mode: "aescbc",
					},
				},
			},
		},

		// scenario 4
		{
			name: "multiple keys and multiple resources",
			input: func() *apiserverconfigv1.EncryptionConfiguration {
				keysRes := []encryptionKeysResourceTuple{
					{
						resource: "secrets",
						keys: []apiserverconfigv1.Key{
							{
								Name:   "34",
								Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc=",
							},
							{
								Name:   "33",
								Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc=",
							},
						},
					},

					{
						resource: "configmaps",
						keys: []apiserverconfigv1.Key{
							{
								Name:   "34",
								Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc=",
							},
							{
								Name:   "33",
								Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc=",
							},
						},
					},
				}
				ec := createEncryptionCfgWithWriteKey(keysRes)
				return ec
			}(),
			output: map[schema.GroupResource]groupResourceKeys{
				{Group: "", Resource: "secrets"}: {
					writeKey: keyAndMode{
						key: apiserverconfigv1.Key{Name: "34", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, mode: "aescbc",
					},
					readKeys: []keyAndMode{
						{key: apiserverconfigv1.Key{Name: "33", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, mode: "aescbc"},
					},
				},
				{Group: "", Resource: "configmaps"}: {
					writeKey: keyAndMode{
						key: apiserverconfigv1.Key{Name: "34", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, mode: "aescbc",
					},
					readKeys: []keyAndMode{
						{key: apiserverconfigv1.Key{Name: "33", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, mode: "aescbc"},
					},
				},
			},
		},

		// scenario 5
		{
			name: "single read key",
			input: func() *apiserverconfigv1.EncryptionConfiguration {
				ec := createEncryptionCfgNoWriteKey("34", "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc=", "secrets")
				return ec
			}(),
			output: map[schema.GroupResource]groupResourceKeys{
				{Group: "", Resource: "secrets"}: {
					writeKey: keyAndMode{
						key: apiserverconfigv1.Key{Name: "", Secret: ""}, mode: "identity",
					},
					readKeys: []keyAndMode{
						{key: apiserverconfigv1.Key{Name: "34", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, mode: "aescbc"},
					},
				},
			},
		},

		// scenario 6
		{
			name: "single read key multiple resources",
			input: func() *apiserverconfigv1.EncryptionConfiguration {
				ec := createEncryptionCfgNoWriteKey("34", "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc=", "secrets", "configmaps")
				return ec
			}(),
			output: map[schema.GroupResource]groupResourceKeys{
				{Group: "", Resource: "secrets"}: {
					writeKey: keyAndMode{
						key: apiserverconfigv1.Key{Name: "", Secret: ""}, mode: "identity",
					},
					readKeys: []keyAndMode{
						{key: apiserverconfigv1.Key{Name: "34", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, mode: "aescbc"},
					},
				},
				{Group: "", Resource: "configmaps"}: {
					writeKey: keyAndMode{
						key: apiserverconfigv1.Key{Name: "", Secret: ""}, mode: "identity",
					},
					readKeys: []keyAndMode{
						{key: apiserverconfigv1.Key{Name: "34", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, mode: "aescbc"},
					},
				},
			},
		},

		// scenario 7
		{
			name: "turn off encryption for single resource",
			input: func() *apiserverconfigv1.EncryptionConfiguration {
				keysRes := encryptionKeysResourceTuple{
					resource: "secrets",
					keys: []apiserverconfigv1.Key{
						{
							Name:   "34",
							Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc=",
						},

						// secretsToProviders puts "fakeIdentityProvider" as last
						{
							Name:   "35",
							Secret: newFakeIdentityEncodedKeyForTest(),
						},
					},
					modes: []string{"aescbc", "aesgcm"},
				}
				ec := createEncryptionCfgNoWriteKeyMultipleReadKeys([]encryptionKeysResourceTuple{keysRes})
				return ec
			}(),
			output: map[schema.GroupResource]groupResourceKeys{
				{Group: "", Resource: "secrets"}: {
					writeKey: keyAndMode{
						key: apiserverconfigv1.Key{Name: "35", Secret: newFakeIdentityEncodedKeyForTest()}, mode: "identity",
					},
					readKeys: []keyAndMode{
						{key: apiserverconfigv1.Key{Name: "34", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, mode: "aescbc"},
					},
				},
			},
		},

		// scenario 8
		{
			name: "turn off encryption for multiple resources",
			input: func() *apiserverconfigv1.EncryptionConfiguration {
				keysRes := []encryptionKeysResourceTuple{
					{
						resource: "secrets",
						keys: []apiserverconfigv1.Key{
							{
								Name:   "34",
								Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc=",
							},

							// secretsToProviders puts "fakeIdentityProvider" as last
							{
								Name:   "35",
								Secret: newFakeIdentityEncodedKeyForTest(),
							},
						},
						modes: []string{"aescbc", "aesgcm"},
					},

					{
						resource: "configmaps",
						keys: []apiserverconfigv1.Key{
							{
								Name:   "34",
								Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc=",
							},

							// secretsToProviders puts "fakeIdentityProvider" as last
							{
								Name:   "35",
								Secret: newFakeIdentityEncodedKeyForTest(),
							},
						},
						modes: []string{"aescbc", "aesgcm"},
					},
				}
				ec := createEncryptionCfgNoWriteKeyMultipleReadKeys(keysRes)
				return ec
			}(),
			output: map[schema.GroupResource]groupResourceKeys{
				{Group: "", Resource: "secrets"}: {
					writeKey: keyAndMode{
						key: apiserverconfigv1.Key{Name: "35", Secret: newFakeIdentityEncodedKeyForTest()}, mode: "identity",
					},
					readKeys: []keyAndMode{
						{key: apiserverconfigv1.Key{Name: "34", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, mode: "aescbc"},
					},
				},

				{Group: "", Resource: "configmaps"}: {
					writeKey: keyAndMode{
						key: apiserverconfigv1.Key{Name: "35", Secret: newFakeIdentityEncodedKeyForTest()}, mode: "identity",
					},
					readKeys: []keyAndMode{
						{key: apiserverconfigv1.Key{Name: "34", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, mode: "aescbc"},
					},
				},
			},
		},

		// scenario 9
		// TODO: encryption on after being off
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			actualOutput := getGRsActualKeys(scenario.input)

			if len(actualOutput) != len(scenario.output) {
				t.Fatalf("expected to get %d GR, got %d", len(scenario.output), len(actualOutput))
			}
			for actualGR, actualKeys := range actualOutput {
				if _, ok := scenario.output[actualGR]; !ok {
					t.Fatalf("unexpected GR %v found", actualGR)
				}
				expectedKeys, _ := scenario.output[actualGR]
				if !cmp.Equal(actualKeys.writeKey, expectedKeys.writeKey, cmp.AllowUnexported(groupResourceKeys{}.writeKey)) {
					t.Fatal(fmt.Errorf("%s", cmp.Diff(actualKeys.writeKey, expectedKeys.writeKey, cmp.AllowUnexported(groupResourceKeys{}.writeKey))))
				}
				if !cmp.Equal(actualKeys.readKeys, expectedKeys.readKeys, cmp.AllowUnexported(groupResourceKeys{}.writeKey)) {
					t.Fatal(fmt.Errorf("%s", cmp.Diff(actualKeys.readKeys, expectedKeys.readKeys, cmp.AllowUnexported(groupResourceKeys{}.writeKey))))
				}
			}
		})
	}
}

func TestGroupResourceKeysToEncryptionConfigRoundtrip(t *testing.T) {
	scenarios := []struct {
		name       string
		grs        []schema.GroupResource
		targetNs   string
		writeKeyIn *corev1.Secret
		readKeysIn []*corev1.Secret
		output     []apiserverconfigv1.ResourceConfiguration
		makeOutput func(writeKey *corev1.Secret, readKeys []*corev1.Secret) []apiserverconfigv1.ResourceConfiguration
	}{
		// scenario 1
		{
			name:       "turn off encryption for single resource",
			grs:        []schema.GroupResource{{Group: "", Resource: "secrets"}},
			targetNs:   "kms",
			writeKeyIn: createEncryptionKeySecretWithRawKey("kms", []schema.GroupResource{{Group: "", Resource: "secrets"}}, 3, newFakeIdentityKeyForTest(), "identity"),
			readKeysIn: []*corev1.Secret{
				createEncryptionKeySecretWithRawKey("kms", []schema.GroupResource{{Group: "", Resource: "secrets"}}, 2, []byte("61def964fb967f5d7c44a2af8dab6865")),
				createExpiredMigratedEncryptionKeySecretWithRawKey("kms", []schema.GroupResource{{Group: "", Resource: "secrets"}}, 1, []byte("61def964fb967f5d7c44a2af8dab6865")),
			},
			makeOutput: func(writeKey *corev1.Secret, readKeys []*corev1.Secret) []apiserverconfigv1.ResourceConfiguration {
				rs := apiserverconfigv1.ResourceConfiguration{}
				rs.Resources = []string{"secrets"}
				rs.Providers = []apiserverconfigv1.ProviderConfiguration{
					{Identity: &apiserverconfigv1.IdentityConfiguration{}},
					{AESCBC: keyToAESConfiguration(readKeys[0])},
					{AESCBC: keyToAESConfiguration(readKeys[1])},
					{AESGCM: keyToAESConfiguration(writeKey)},
				}
				return []apiserverconfigv1.ResourceConfiguration{rs}
			},
		},

		// scenario 2
		{
			name:       "order of the keys is preserved, the write key comes first, then the read keys finally the identity comes last",
			grs:        []schema.GroupResource{{Group: "", Resource: "secrets"}},
			targetNs:   "kms",
			writeKeyIn: createEncryptionKeySecretWithRawKey("kms", []schema.GroupResource{{Group: "", Resource: "secrets"}}, 3, []byte("16f87d5793a3cb726fb9be7ef8211821")),
			readKeysIn: []*corev1.Secret{
				createEncryptionKeySecretWithRawKey("kms", []schema.GroupResource{{Group: "", Resource: "secrets"}}, 2, []byte("558bf68d6d8ab5dd819eec02901766c1")),
				createExpiredMigratedEncryptionKeySecretWithRawKey("kms", []schema.GroupResource{{Group: "", Resource: "secrets"}}, 1, []byte("61def964fb967f5d7c44a2af8dab6865")),
			},
			makeOutput: func(writeKey *corev1.Secret, readKeys []*corev1.Secret) []apiserverconfigv1.ResourceConfiguration {
				rs := apiserverconfigv1.ResourceConfiguration{}
				rs.Resources = []string{"secrets"}
				rs.Providers = []apiserverconfigv1.ProviderConfiguration{
					{AESCBC: keyToAESConfiguration(writeKey)},
					{AESCBC: keyToAESConfiguration(readKeys[0])},
					{AESCBC: keyToAESConfiguration(readKeys[1])},
					{Identity: &apiserverconfigv1.IdentityConfiguration{}},
				}
				return []apiserverconfigv1.ResourceConfiguration{rs}
			},
		},

		// scenario 3
		{
			name:       "the identity comes first up when there are no keys",
			grs:        []schema.GroupResource{{Group: "", Resource: "secrets"}},
			targetNs:   "kms",
			makeOutput: func(writeKey *corev1.Secret, readKeys []*corev1.Secret) []apiserverconfigv1.ResourceConfiguration {
				rs := apiserverconfigv1.ResourceConfiguration{}
				rs.Resources = []string{"secrets"}
				rs.Providers = []apiserverconfigv1.ProviderConfiguration{{Identity: &apiserverconfigv1.IdentityConfiguration{}}}
				return []apiserverconfigv1.ResourceConfiguration{rs}
			},
		},

		// scenario 4
		{
			name:       "order of the keys is preserved, the write key comes first, then the read keys finally the identity comes last - multiple resources",
			grs:        []schema.GroupResource{{Group: "", Resource: "secrets"}, {Group: "", Resource: "configmaps"}},
			targetNs:   "kms",
			writeKeyIn: createEncryptionKeySecretWithRawKey("kms", []schema.GroupResource{{Group: "", Resource: "secrets"}, {Group: "", Resource: "configmaps"}}, 3, []byte("16f87d5793a3cb726fb9be7ef8211821")),
			readKeysIn: []*corev1.Secret{
				createEncryptionKeySecretWithRawKey("kms", []schema.GroupResource{{Group: "", Resource: "secrets"}, {Group: "", Resource: "configmaps"}}, 2, []byte("558bf68d6d8ab5dd819eec02901766c1")),
				createExpiredMigratedEncryptionKeySecretWithRawKey("kms", []schema.GroupResource{{Group: "", Resource: "secrets"}, {Group: "", Resource: "configmaps"}}, 1, []byte("61def964fb967f5d7c44a2af8dab6865")),
			},
			makeOutput: func(writeKey *corev1.Secret, readKeys []*corev1.Secret) []apiserverconfigv1.ResourceConfiguration {
				rc:= apiserverconfigv1.ResourceConfiguration{}
				rc.Resources = []string{"configmaps"}
				rc.Providers = []apiserverconfigv1.ProviderConfiguration{
					{AESCBC: keyToAESConfiguration(writeKey)},
					{AESCBC: keyToAESConfiguration(readKeys[0])},
					{AESCBC: keyToAESConfiguration(readKeys[1])},
					{Identity: &apiserverconfigv1.IdentityConfiguration{}},
				}

				rs := apiserverconfigv1.ResourceConfiguration{}
				rs.Resources = []string{"secrets"}
				rs.Providers = []apiserverconfigv1.ProviderConfiguration{
					{AESCBC: keyToAESConfiguration(writeKey)},
					{AESCBC: keyToAESConfiguration(readKeys[0])},
					{AESCBC: keyToAESConfiguration(readKeys[1])},
					{Identity: &apiserverconfigv1.IdentityConfiguration{}},
				}

				return []apiserverconfigv1.ResourceConfiguration{rc, rs}
			},
		},

		// scenario 5
		{
			name:       "turn off encryption for multiple resources",
			grs:        []schema.GroupResource{{Group: "", Resource: "secrets"}, {Group: "", Resource: "configmaps"}},
			targetNs:   "kms",
			writeKeyIn: createEncryptionKeySecretWithRawKey("kms", []schema.GroupResource{{Group: "", Resource: "secrets"}, {Group: "", Resource: "configmaps"}}, 3, newFakeIdentityKeyForTest(), "identity"),
			readKeysIn: []*corev1.Secret{
				createEncryptionKeySecretWithRawKey("kms", []schema.GroupResource{{Group: "", Resource: "secrets"}, {Group: "", Resource: "configmaps"}}, 2, []byte("61def964fb967f5d7c44a2af8dab6865")),
				createExpiredMigratedEncryptionKeySecretWithRawKey("kms", []schema.GroupResource{{Group: "", Resource: "secrets"}}, 1, []byte("61def964fb967f5d7c44a2af8dab6865")),
			},
			makeOutput: func(writeKey *corev1.Secret, readKeys []*corev1.Secret) []apiserverconfigv1.ResourceConfiguration {
				rc := apiserverconfigv1.ResourceConfiguration{}
				rc.Resources = []string{"configmaps"}
				rc.Providers = []apiserverconfigv1.ProviderConfiguration{
					{Identity: &apiserverconfigv1.IdentityConfiguration{}},
					{AESCBC: keyToAESConfiguration(readKeys[0])},
					{AESCBC: keyToAESConfiguration(readKeys[1])},
					{AESGCM: keyToAESConfiguration(writeKey)},
				}

				rs := apiserverconfigv1.ResourceConfiguration{}
				rs.Resources = []string{"secrets"}
				rs.Providers = []apiserverconfigv1.ProviderConfiguration{
					{Identity: &apiserverconfigv1.IdentityConfiguration{}},
					{AESCBC: keyToAESConfiguration(readKeys[0])},
					{AESCBC: keyToAESConfiguration(readKeys[1])},
					{AESGCM: keyToAESConfiguration(writeKey)},
				}
				return []apiserverconfigv1.ResourceConfiguration{rc, rs}
			},
		},

		// scenario 6
		// TODO: encryption on after being off
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			grState := map[schema.GroupResource]keysState{}
			for _, gr := range scenario.grs {
				ks := keysState{
					targetNamespace: scenario.targetNs,
					readSecrets:     scenario.readKeysIn,
					writeSecret:     scenario.writeKeyIn,
				}
				grState[gr] = ks

			}
			actualOutput := getResourceConfigs(grState)
			expectedOutput := scenario.makeOutput(scenario.writeKeyIn, scenario.readKeysIn)

			if !cmp.Equal(actualOutput, expectedOutput) {
				t.Fatal(fmt.Errorf("%s", cmp.Diff(actualOutput, expectedOutput)))
			}
		})
	}
}

func keyToAESConfiguration(key *corev1.Secret) *apiserverconfigv1.AESConfiguration {
	return &apiserverconfigv1.AESConfiguration{
		Keys: []apiserverconfigv1.Key{
			{
				Name:   strings.Split(key.Name, "-")[2],
				Secret: base64.StdEncoding.EncodeToString(key.Data[encryptionSecretKeyDataForTest]),
			},
		},
	}
}
