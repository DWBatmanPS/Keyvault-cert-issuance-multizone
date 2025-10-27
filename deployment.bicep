@description('The name of the function app that you wish to create.')
@maxLength(14)
param appNamePrefix string = 'acmetestapp'
param appNameSuffix string = 'dwtest'

@description('The location of the function app that you wish to create.')
param location string = resourceGroup().location

@description('Email address for ACME account.')
param mailAddress string 


@description('Enter the base URL of an existing Key Vault. (ex. https://example.vault.azure.net)')
param keyVaultName string

param PARENTDNSZONE string
param PARENTDNSZONE2 string
param PARENTDNSZONE3 string
param PARENTDNSZONE4 string

param deployPrivateEndpoints bool = false

var privateEndpoints_storagepe_name = 'pe-${storageAccountName}'
var privateEndpoints_storageTablepe_name = 'pe-table-${storageAccountName}'
var tenantId = subscription().tenantId
var functionAppName = 'func-${appNamePrefix}-${appNameSuffix}'
var appServicePlanName = 'plan-${appNamePrefix}-${appNameSuffix}'
var appInsightsName = 'appi-${appNamePrefix}-${appNameSuffix}'
var workspaceName = 'log-${appNamePrefix}-${appNameSuffix}'
var storageAccountName = 'st${appNamePrefix}${appNameSuffix}'
var KVCertOfficerRoleId = resourceId('Microsoft.Authorization/roleDefinitions/', 'a4417e6f-fecd-4de8-b567-7b0420556985')
var KVCryptoOfficerRoleId = resourceId('Microsoft.Authorization/roleDefinitions/', '14b46e9e-c2b7-41b4-b07b-48a6ebf60603')
var KVSecOfficerRoleId = resourceId('Microsoft.Authorization/roleDefinitions/', 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7')
var dnsZoneContributorRoleId = resourceId('Microsoft.Authorization/roleDefinitions', 'befefa01-2a29-4197-83a8-272ff33ce314')
var blobDataContributorRoleId = resourceId('Microsoft.Authorization/roleDefinitions', 'ba92f5b4-2d11-453d-a403-e96b0029c9fe')
var queueDataContributorRoleId = resourceId('Microsoft.Authorization/roleDefinitions', '974c5e8b-45b9-4653-ba55-5f855dd0fb88')
var tableDataContributorRoleId = resourceId('Microsoft.Authorization/roleDefinitions', '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3')
var acmebotAppSettings = [
  {
    name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
    value: appInsights.properties.ConnectionString
  }
  {
    name: 'AzureWebJobsStorage__accountName'
    value: storageAccount.name
  }
  {
  name: 'APP_STORAGE_ACCOUNT_NAME'
  value: storageAccount.name
  }
   {
    name: 'AzureWebJobsStorage__blobServiceUri'
    value: 'https://${storageAccount.name}.blob.${environment().suffixes.storage}'
  }
  {
    name: 'AzureWebJobsStorage__queueServiceUri'
    value: 'https://${storageAccount.name}.queue.${environment().suffixes.storage}'
  }
  {
    name: 'AzureWebJobsStorage__tableServiceUri'
    value: 'https://${storageAccount.name}.table.${environment().suffixes.storage}'
  }
  {
    name: 'LE_EMAIL'
    value: mailAddress
  }
  {
    name: 'RESOURCE_GROUP'
    value: resourceGroup().name
  }
  {
    name: 'AZURE_SUBSCRIPTION_ID'
    value: subscription().subscriptionId
  }
  {
    name: 'LE_USE_STAGING'
    value: 'true'
  }
  {
    name: 'LE_VERBOSE'
    value: 'true'
  }
  {
    name: 'LE_DRY_RUN'
    value: 'true'
  }
  {
    name: 'KEYVAULT_CERT_NAME'
    value: 'endcert'
  }
  {
    name: 'ACCOUNT_KEY_SECRET_NAME'
    value: 'acme-account-prod'
  }
  {
    name: 'CLEANUP_DNS'
    value: 'true'
  }
  {
    name: 'PFX_PASSWORD'
    value: 'OptionalStrongPassword'
  }
  {
    name: 'ADDITIONAL_NAMES'
    value: ''
  }
  {
    name: 'MAX_PROPAGATION_MINUTES'
    value: '2'
  }
  {
    name: 'MAX_CHALLENGE_MINUTES'
    value: '5'
  }
]

resource zone 'Microsoft.Network/dnsZones@2018-05-01' = {
  name: PARENTDNSZONE
  location: 'global'
}

resource DNSZone_roleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(functionAppName, 'befefa01-2a29-4197-83a8-272ff33ce314', PARENTDNSZONE)
  scope:zone
  properties: {
    roleDefinitionId: dnsZoneContributorRoleId // DNS Zone Contributor
    principalId: functionApp.identity.principalId
  }
}

resource zone2 'Microsoft.Network/dnsZones@2018-05-01' = {
  name: PARENTDNSZONE2
  location: 'global'
}

resource DNSZone2_roleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(functionAppName, 'befefa01-2a29-4197-83a8-272ff33ce314', PARENTDNSZONE2)
  scope:zone2
  properties: {
    roleDefinitionId: dnsZoneContributorRoleId // DNS Zone Contributor
    principalId: functionApp.identity.principalId
  }
}

resource zone3 'Microsoft.Network/dnsZones@2018-05-01' = {
  name: PARENTDNSZONE3
  location: 'global'
}

resource DNSZone3_roleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(functionAppName, 'befefa01-2a29-4197-83a8-272ff33ce314', PARENTDNSZONE3)
  scope:zone3
  properties: {
    roleDefinitionId: dnsZoneContributorRoleId // DNS Zone Contributor
    principalId: functionApp.identity.principalId
  }
}

resource zone4 'Microsoft.Network/dnsZones@2018-05-01' = {
  name: PARENTDNSZONE4
  location: 'global'
}

resource DNSZone4_roleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(functionAppName, 'befefa01-2a29-4197-83a8-272ff33ce314', PARENTDNSZONE4)
  scope:zone4
  properties: {
    roleDefinitionId: dnsZoneContributorRoleId // DNS Zone Contributor
    principalId: functionApp.identity.principalId
  }
}

resource storageAccount 'Microsoft.Storage/storageAccounts@2025-01-01' = {
  name: storageAccountName
  location: location
  kind: 'StorageV2'
  sku: {
    name: 'Standard_LRS'
  }
  properties: {
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_2'
    defaultToOAuthAuthentication: true
    publicNetworkAccess: 'Enabled'
    allowCrossTenantReplication: false
    allowSharedKeyAccess: false
    networkAcls: {
      bypass: 'AzureServices'
      virtualNetworkRules: []
      ipRules: []
      defaultAction: 'Allow'
    }
  }
}

resource Blob_Services 'Microsoft.Storage/storageAccounts/blobServices@2023-01-01' = {
  parent: storageAccount
  name: 'default'
  properties: {
  }
}

resource Table_Services 'Microsoft.Storage/storageAccounts/tableServices@2023-01-01' = {
  parent: storageAccount
  name: 'default'
  properties: {
  }
}

resource storageBlobRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(functionApp.name, blobDataContributorRoleId)
  scope: storageAccount
  properties: {
    roleDefinitionId: blobDataContributorRoleId
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource storageQueueRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(functionApp.name, queueDataContributorRoleId)
  scope: storageAccount
  properties: {
    roleDefinitionId: queueDataContributorRoleId
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource storageTableRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(functionApp.name, tableDataContributorRoleId)
  scope: storageAccount
  properties: {
    roleDefinitionId: tableDataContributorRoleId
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource appServicePlan 'Microsoft.Web/serverfarms@2024-11-01' = {
  name: appServicePlanName
  location: location
  sku: {
    name: 'FC1'
    tier: 'FlexConsumption'
    size: 'FC1'
    family: 'FC'
    capacity: 0
  }
  kind: 'functionapp'
  properties: {
    perSiteScaling: false
    elasticScaleEnabled: false
    maximumElasticWorkerCount: 1
    isSpot: false
    reserved: true
    isXenon: false
    hyperV: false
    targetWorkerCount: 0
    targetWorkerSizeId: 0
    zoneRedundant: false
    asyncScalingEnabled: false
  }
}

resource privateEndpoints_storagepe_name_resource 'Microsoft.Network/privateEndpoints@2024-07-01' = if(deployPrivateEndpoints) {
  name: privateEndpoints_storagepe_name
  location: location
  properties: {
    privateLinkServiceConnections: [
      {
        name: privateEndpoints_storagepe_name
        properties: {
          privateLinkServiceId: storageAccount.id
          groupIds: [
            'blob'
          ]
        }
      }
    ]
    customNetworkInterfaceName: '${privateEndpoints_storagepe_name}-nic'
    subnet: {
      id: vNet.properties.subnets[1].id
    }
  }
}

resource storprivateDNSZone 'Microsoft.Network/privateDnsZones@2020-06-01' = if (deployPrivateEndpoints) {
  name: 'privatelink.blob.${environment().suffixes.storage}'
  location: 'global'
}

resource privateEndpoints_storageTablepe_name_resource 'Microsoft.Network/privateEndpoints@2024-07-01' = if (deployPrivateEndpoints) {
  name: privateEndpoints_storageTablepe_name
  location: location
  properties: {
    privateLinkServiceConnections: [
      {
        name: privateEndpoints_storageTablepe_name
        properties: {
          privateLinkServiceId: storageAccount.id
          groupIds: [
            'table'
          ]
        }
      }
    ]
    customNetworkInterfaceName: '${privateEndpoints_storageTablepe_name}-nic'
    subnet: {
      id: vNet.properties.subnets[1].id
    }
  }
}

resource storprivateTableDNSZone 'Microsoft.Network/privateDnsZones@2020-06-01' = if (deployPrivateEndpoints){
  name: 'privatelink.table.${environment().suffixes.storage}'
  location: 'global'
}

resource storprivateDNSZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2023-04-01' = if (deployPrivateEndpoints) { 
  parent: privateEndpoints_storagepe_name_resource
  name: '${storageAccountName}ZoneGroup'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'default'
        properties: {
           privateDnsZoneId: storprivateDNSZone.id
        }
      }
    ]
  }
}

resource storprivateTableDNSZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2023-04-01' = if (deployPrivateEndpoints){
  parent: privateEndpoints_storageTablepe_name_resource
  name: '${storageAccountName}TableZoneGroup'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'default'
        properties: {
           privateDnsZoneId: storprivateTableDNSZone.id
        }
      }
    ]
  }
}

resource stordnsvirtualNetworkLink_File 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2018-09-01' = if (deployPrivateEndpoints) {
  parent: storprivateDNSZone
  name: '${privateEndpoints_storagepe_name}_to_${last(split(vNet.id, '/'))}'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: vNet.id
    }
  }
}

resource storTablednsvirtualNetworkLink_File 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2018-09-01' = if (deployPrivateEndpoints) {
  parent: storprivateTableDNSZone
  name: '${privateEndpoints_storageTablepe_name}_to_${last(split(vNet.id, '/'))}'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: vNet.id
    }
  }
}

resource privateEndpoint_NIC_storpe 'Microsoft.Network/networkInterfaces@2024-07-01' existing = {
  name: '${privateEndpoints_storagepe_name}-nic'
  scope: resourceGroup()
  dependsOn: [
    privateEndpoints_storagepe_name_resource 
  ]
}

resource storPE_A_Record 'Microsoft.Network/privateDnsZones/A@2020-06-01' = if (deployPrivateEndpoints) {
  parent: storprivateDNSZone
  name: storageAccount.name
  properties: {
    ttl: 3600
    aRecords: [
      {
        ipv4Address: privateEndpoint_NIC_storpe.properties.ipConfigurations[0].properties.privateIPAddress
      }
    ]
  }
}

resource privateEndpoint_NIC_storTablepe 'Microsoft.Network/networkInterfaces@2024-07-01' existing = {
  name: '${privateEndpoints_storageTablepe_name}-nic'
  scope: resourceGroup()
  dependsOn: [
    privateEndpoints_storageTablepe_name_resource
  ]
}

resource storTablePE_A_Record 'Microsoft.Network/privateDnsZones/A@2020-06-01' = if (deployPrivateEndpoints) {
  parent: storprivateTableDNSZone
  name: storageAccount.name
  properties: {
    ttl: 3600
    aRecords: [
      {
        ipv4Address: privateEndpoint_NIC_storTablepe.properties.ipConfigurations[0].properties.privateIPAddress
      }
    ]
  }
}


resource workspace 'Microsoft.OperationalInsights/workspaces@2025-02-01' = {
  name: workspaceName
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
  }
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: appInsightsName
  location: location
  kind: 'web'
  tags: {
    'hidden-link:${resourceGroup().id}/providers/Microsoft.Web/sites/${functionAppName}': 'Resource'
  }
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: workspace.id
  }
}

resource functionApp 'Microsoft.Web/sites@2024-11-01' = {
  name: functionAppName
  location: location
  kind: 'functionapp'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    clientAffinityEnabled: false
    httpsOnly: true
    serverFarmId: appServicePlan.id
    siteConfig: {
      numberOfWorkers: 1
      appSettings: concat(acmebotAppSettings)
      netFrameworkVersion: 'v8.0'
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      scmMinTlsVersion: '1.2'
      cors: {
        allowedOrigins: ['https://portal.azure.com']
        supportCredentials: false
      }
    }
    virtualNetworkSubnetId: vNet.properties.subnets[0].id
    functionAppConfig: {
      deployment: {
        storage: {
          type: 'blobContainer'
          value: 'https://${storageAccountName}.blob.${environment().suffixes.storage}'
          authentication:{
            type: 'SystemAssignedIdentity'
          }
        }
      }
      runtime: {
        name: 'dotnet-isolated'
        version: '8.0'
      }
      scaleAndConcurrency: {
        instanceMemoryMB: 512
        maximumInstanceCount: 40
        triggers:{
          http: {
            perInstanceConcurrency: 100
          }
        }
        alwaysReady:[
          {
            instanceCount: 0
            name: 'http'
          }
        ]
      }
    }

  }
}

resource sites_functionapp_subnet_link 'Microsoft.Web/sites/virtualNetworkConnections@2024-11-01' = {
  parent: functionApp
  name: '${functionAppName}-vnet-link'
  properties: {
    vnetResourceId: vNet.properties.subnets[0].id
    isSwift: true
  }
}

resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: keyVaultName
  location: location
  properties: {
    enabledForDeployment: true
    enabledForDiskEncryption: true
    enabledForTemplateDeployment: true
    tenantId: tenantId
    enableSoftDelete: true
    softDeleteRetentionInDays: 60
    enableRbacAuthorization: true
    sku: {
      name: 'standard'
      family: 'A'
    }
    networkAcls: {
      defaultAction: 'Allow'
      bypass: 'AzureServices'
    }
  }
}

resource keyVault_CertOfficerroleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(functionAppName, KVCertOfficerRoleId)
  scope:kv
  properties: {
    roleDefinitionId: KVCertOfficerRoleId
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource keyVault_CryptoOfficerroleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(functionAppName, KVCryptoOfficerRoleId)
  scope:kv
  properties: {
    roleDefinitionId: KVCryptoOfficerRoleId
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource keyVault_SecOfficerroleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(functionAppName, KVSecOfficerRoleId)
  scope:kv
  properties: {
    roleDefinitionId: KVSecOfficerRoleId
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource vNet 'Microsoft.Network/virtualNetworks@2024-07-01' = {
  location: location
  name: 'vnet-${appNamePrefix}-${substring(uniqueString(resourceGroup().id, deployment().name), 0, 4)}'
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.0.0.0/16'
      ]
    }
    subnets: [
      {
        name: 'functionapp-subnet'
        properties: {
          addressPrefix: '10.0.0.0/24'
          delegations: [
            {
              name:'delegation'
              properties: {
                serviceName: 'Microsoft.App/environments'
              }
            }
          ]
          serviceEndpoints: [
            {
              service: 'Microsoft.Storage'
              locations: [
                'canadacentral'
                'canadaeast'
              ]
            }
          ]
        }
      }
      {
        name: 'kv-pe-subnet'
        properties: {
          addressPrefix: '10.0.1.0/24'      
        }
      }
    ]
  }
}

output functionAppName string = functionApp.name
output principalId string = functionApp.identity.principalId
output tenantId string = functionApp.identity.tenantId
