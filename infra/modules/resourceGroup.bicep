param name string
param location string

resource rg 'Microsoft.Resources/resourceGroups@2024-07-01' = {
  name: name
  location: location
  tags: {
    Environment: 'production'
    Project: 'ai-waf'
  }
}

output name string = rg.name
