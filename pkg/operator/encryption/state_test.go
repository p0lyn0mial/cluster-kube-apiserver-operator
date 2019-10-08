package encryption

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

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
				}
				ec := createEncryptionCfgNoWriteKeyMultipleReadKeys([]encryptionKeysResourceTuple{keysRes})
				return ec
			}(),
			output: map[schema.GroupResource]groupResourceKeys{
				{Group: "", Resource: "secrets"}: {
					writeKey: keyAndMode{
						key: apiserverconfigv1.Key{Name: "", Secret: ""}, mode: "identity",
					},
					readKeys: []keyAndMode{
						{key: apiserverconfigv1.Key{Name: "34", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, mode: "aescbc"},
						{key: apiserverconfigv1.Key{Name: "35", Secret: newFakeIdentityEncodedKeyForTest()}, mode: "aescbc"},
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
					},
				}
				ec := createEncryptionCfgNoWriteKeyMultipleReadKeys(keysRes)
				return ec
			}(),
			output: map[schema.GroupResource]groupResourceKeys{
				{Group: "", Resource: "secrets"}: {
					writeKey: keyAndMode{
						key: apiserverconfigv1.Key{Name: "", Secret: ""}, mode: "identity",
					},
					readKeys: []keyAndMode{
						{key: apiserverconfigv1.Key{Name: "34", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, mode: "aescbc"},
						{key: apiserverconfigv1.Key{Name: "35", Secret: newFakeIdentityEncodedKeyForTest()}, mode: "aescbc"},
					},
				},

				{Group: "", Resource: "configmaps"}: {
					writeKey: keyAndMode{
						key: apiserverconfigv1.Key{Name: "", Secret: ""}, mode: "identity",
					},
					readKeys: []keyAndMode{
						{key: apiserverconfigv1.Key{Name: "34", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, mode: "aescbc"},
						{key: apiserverconfigv1.Key{Name: "35", Secret: newFakeIdentityEncodedKeyForTest()}, mode: "aescbc"},
					},
				},
			},
		},
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
