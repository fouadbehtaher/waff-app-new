targetScope = 'subscription'

param location string = 'eastus2'
param environmentName string = 'aiwaf'
param openAIApiKey string = ''
param customAiApiUrl string = ''
param customAiApiKey string = ''
param upstreamUrl string = ''

var resourceGroupName = 'rg-${environmentName}'
var containerAppEnvName = 'cae-${environmentName}'
var containerAppName = 'ca-${environmentName}-waf'
var containerRegistryName = 'acr${uniqueString(subscription().id, environmentName)}'
var logAnalyticsName = 'law-${environmentName}'

module resourceGroup './modules/resourceGroup.bicep' = {
  name: 'rgDeployment'
  params: {
    name: resourceGroupName
    location: location
  }
}

module logAnalytics './modules/logAnalytics.bicep' = {
  name: 'logAnalyticsDeployment'
  params: {
    name: logAnalyticsName
    location: location
    resourceGroupName: resourceGroup.outputs.name
  }
}

module containerRegistry './modules/containerRegistry.bicep' = {
  name: 'acrDeployment'
  params: {
    name: containerRegistryName
    location: location
    resourceGroupName: resourceGroup.outputs.name
  }
}

module containerAppEnv './modules/containerAppEnvironment.bicep' = {
  name: 'containerAppEnvDeployment'
  params: {
    name: containerAppEnvName
    location: location
    resourceGroupName: resourceGroup.outputs.name
    logAnalyticsWorkspaceId: logAnalytics.outputs.workspaceId
  }
}

module containerApp './modules/containerApp.bicep' = {
  name: 'containerAppDeployment'
  params: {
    name: containerAppName
    location: location
    resourceGroupName: resourceGroup.outputs.name
    environmentId: containerAppEnv.outputs.environmentId
    containerRegistryLoginServer: containerRegistry.outputs.loginServer
    openAIApiKey: openAIApiKey
    customAiApiUrl: customAiApiUrl
    customAiApiKey: customAiApiKey
    upstreamUrl: upstreamUrl
  }
}

output wafUrl string = containerApp.outputs.fqdn
output containerRegistryLoginServer string = containerRegistry.outputs.loginServer
