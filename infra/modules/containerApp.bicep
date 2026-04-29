param name string
param location string
param resourceGroupName string
param environmentId string
param containerRegistryLoginServer string
param openAIApiKey string
param customAiApiUrl string
param customAiApiKey string
param upstreamUrl string

@secure()
param openAIApiKeySecure string = openAIApiKey

@secure()
param customAiApiKeySecure string = customAiApiKey

resource containerApp 'Microsoft.App/containerApps@2024-02-02-preview' = {
  name: name
  location: location
  properties: {
    managedEnvironmentId: environmentId
    configuration: {
      ingress: {
        external: true
        targetPort: 8000
        transport: 'auto'
        allowInsecure: false
      }
      secrets: [
        {
          name: 'openai-api-key'
          value: openAIApiKeySecure
        }
        {
          name: 'custom-ai-api-key'
          value: customAiApiKeySecure
        }
      ]
      registries: [
        {
          server: containerRegistryLoginServer
          identity: 'system'
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'waf-api'
          image: '${containerRegistryLoginServer}/ai-waf:latest'
          resources: {
            cpu: json('1.0')
            memory: '2Gi'
          }
          env: [
            {
              name: 'UPSTREAM_URL'
              value: upstreamUrl
            }
            {
              name: 'OPENAI_API_KEY'
              secretRef: 'openai-api-key'
            }
            {
              name: 'CUSTOM_AI_API_URL'
              value: customAiApiUrl
            }
            {
              name: 'CUSTOM_AI_API_KEY'
              secretRef: 'custom-ai-api-key'
            }
          ]
          probes: [
            {
              type: 'Liveness'
              httpGet: {
                path: '/health'
                port: 8000
              }
              initialDelaySeconds: 10
              periodSeconds: 30
            }
            {
              type: 'Readiness'
              httpGet: {
                path: '/health'
                port: 8000
              }
              initialDelaySeconds: 5
              periodSeconds: 10
            }
          ]
        }
      ]
      scale: {
        minReplicas: 2
        maxReplicas: 10
        rules: [
          {
            name: 'http-scaler'
            http: {
              metadata: {
                concurrentRequests: '50'
              }
            }
          }
        ]
      }
    }
  }
}

output fqdn string = containerApp.properties.configuration.ingress.fqdn
output containerAppId string = containerApp.id
