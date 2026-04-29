param name string
param location string
param resourceGroupName string
param logAnalyticsWorkspaceId string

resource containerAppEnv 'Microsoft.App/managedEnvironments@2024-02-02-preview' = {
  name: name
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: split(logAnalyticsWorkspaceId, '/')[8]
        sharedKey: listKeys(logAnalyticsWorkspaceId, '2023-09-01').primarySharedKey
      }
    }
    zoneRedundant: false
  }
}

output environmentId string = containerAppEnv.id
output environmentName string = containerAppEnv.name
