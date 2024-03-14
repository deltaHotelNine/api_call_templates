# Function to check for and install a module
function Install-ModuleIfMissing {
  param(
    [string]$moduleName
  )

  if (-not (Get-Module -ListAvailable -Name $moduleName)) {
    Install-Module -Name $moduleName -Scope CurrentUser -Force
    Import-Module -Name $moduleName
  }
  else {
    Import-Module -Name $moduleName
  }
}

# Check if System.Web assembly is loaded, if not, load it
if (-not ([System.Management.Automation.PSTypeName]'System.Web.HttpUtility').Type) {
  Add-Type -AssemblyName System.Web
}

# Function to get a secret from Azure Key Vault
function Get-KeyVaultSecret {
  param(
    [string]$vaultName,
    [string]$secretName,
    [string]$environment = "AzureUSGovernment",
    [string]$subscriptionId
  )

  $null = Connect-AzAccount -Environment $environment -Subscription $subscriptionId

  # Get the secret from the Key Vault
  $secret = Get-AzKeyVaultSecret -VaultName $vaultName -Name $secretName -AsPlainText

  # Return the secret value
  return $secret
}

# Function to generate the authorization signature for Cosmos DB
function Get-MasterKeyAuthorizationSignature {
  param(
    [string]$verb,
    [string]$resourceType,
    [string]$resourceLink,
    [string]$date,
    [string]$masterKey,
    [string]$keyType = "master",
    [string]$tokenVersion = "1.0"
  )

  # Construct the payload
  $payload = "$($verb.ToLower())`n$resourceType`n$resourceLink`n$($date.toLower())`n`n"

  # Compute the HMACSHA256 hash of the payload
  $hmacSha = New-Object System.Security.Cryptography.HMACSHA256
  $hmacSha.key = [System.Convert]::FromBase64String($masterKey)
  $hashPayLoad = $hmacSha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($payload))
  $signature = [System.Convert]::ToBase64String($hashPayLoad)

  # Construct the authorization string
  $authSet = [System.Web.HttpUtility]::UrlEncode("type=$keyType&ver=$tokenVersion&sig=$signature")

  return $authSet
}

# Function to query a Cosmos DB collection
function Invoke-CosmosDBQuery {
  param(
    [ValidateSet("GET", "POST", "PUT", "DELETE")]
    [string]$verb = "POST",
    [string]$resourceType = "docs",
    [string]$cosmosAccount,
    [string]$databaseName,
    [string]$collectionName,
    [ValidateNotNullOrEmpty()]
    [string]$masterKey,
    [string]$queryString
  )

  # Construct the resource link
  $resourceLink = "dbs/$databaseName/colls/$collectionName"
  $date = [DateTime]::UtcNow.ToString("r")

  # Generate the authorization token
  $authToken = Get-MasterKeyAuthorizationSignature -verb $verb -resourceType $resourceType -resourceLink $resourceLink -date $date -masterKey $masterKey

  # Construct the URI for the request
  $uri = "https://$cosmosAccount.documents.azure.us/dbs/$databaseName/colls/$collectionName/docs"

  # Define the headers for the request
  $headers = @{
    "authorization"                              = $authToken
    "x-ms-date"                                  = $date
    "x-ms-version"                               = "2018-12-31"
    "x-ms-documentdb-isquery"                    = $true
    "x-ms-documentdb-query-enablecrosspartition" = $true
    "Content-Type"                               = "application/query+json"
  }

  # Define the query
  $query = @{
    query      = $queryString
    parameters = @()
  }

  # Convert the query to JSON
  $body = $query | ConvertTo-Json

  # Send the request and handle any exceptions
  try {
    return Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $body
  }
  catch {
    Write-Error "Failed to query Cosmos DB: $_"
  }
}

# Check for and install necessary modules
Install-ModuleIfMissing -moduleName "Az.Accounts"
Install-ModuleIfMissing -moduleName "Az.KeyVault"

# Prompt the user for the necessary parameters
$vaultName = Read-Host -Prompt "Enter your Key Vault name (leave blank for default: key_vault_name)"
if ($vaultName -eq '') { $vaultName = "<key_vault_name>" }

$secretName = Read-Host -Prompt "Enter your secret name (leave blank for default: secret_name)"
if ($secretName -eq '') { $secretName = "<secret_name>" }

$subscriptionId = Read-Host -Prompt "Enter your subscription ID (leave blank for default: subscription_id)"
if ($subscriptionId -eq '') { $subscriptionId = "<subscription_id>" }

$cosmosAccount = Read-Host -Prompt "Enter your Cosmos DB account name (leave blank for default: cosmosdb_account)"
if ($cosmosAccount -eq '') { $cosmosAccount = "<cosmosdb_account>" }

$databaseName = Read-Host -Prompt "Enter your database name (leave blank for default: database_name)"
if ($databaseName -eq '') { $databaseName = "<database_name>" }

$collectionName = Read-Host -Prompt "Enter your collection name (leave blank for default: collection_name)"
if ($collectionName -eq '') { $collectionName = "<collection_name>" }

$queryString = Read-Host -Prompt "Enter your query string (leave blank for default: SELECT * from c\)"
if ($queryString -eq '') { $queryString = "SELECT * FROM c" }

# Usage
$masterKey = Get-KeyVaultSecret -vaultName $vaultName -secretName $secretName -subscriptionId $subscriptionId
$response = Invoke-CosmosDBQuery -cosmosAccount $cosmosAccount -databaseName $databaseName -collectionName $collectionName -masterKey $masterKey -queryString $queryString
$response

# Clear the master key from memory
$masterKey = $null
