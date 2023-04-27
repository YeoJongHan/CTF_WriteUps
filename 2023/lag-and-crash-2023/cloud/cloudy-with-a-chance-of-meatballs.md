# ☁ Cloudy with a chance of meatballs

## Description

> Today in school, I learnt to code in HTML! View my brand new website! [www.lncctf2023.tk](http://www.lncctf2023.tk/)

## TL;DR

* Use nslookup to get cloud domain name
* Enumerate the blob service to find /private container
* Get `instructions.txt` from container, it contains azure creds
* Login to az cli using the creds
* Generate token and login using azure powershell
* Enumerate the storage accounts and find flag under the "lncctf2023private" storage account

## Solution

### Where is the cloud?

Visiting the site provided, we are given a static page with nothing else on the site.

<figure><img src="../../../.gitbook/assets/image (3) (1) (4) (1).png" alt=""><figcaption><p>www.lncctf2023.tk</p></figcaption></figure>

From point 3, we guess that we will be working with the Azure cloud service.

One trick to find the cloud domain name is to use nslookup to look for other aliases of the site:

<figure><img src="../../../.gitbook/assets/image (11) (2) (1).png" alt=""><figcaption><p>nslookup</p></figcaption></figure>

And of course, the cloud domain name is `lncctf2023`. We can now enumerate the different services.&#x20;

### Service Enumeration

I searched up cloud enumeration tools and ended up using the [cloud\_enum.py](https://github.com/initstring/cloud\_enum) tool as it works well enough.

<figure><img src="../../../.gitbook/assets/image (40).png" alt=""><figcaption><p>Service Enumeration</p></figcaption></figure>

From the enumeration, we can see that there is a `/private` blob container containing a file called `instructions.txt`.

We can grab the file by visiting the endpoint as it is open to the public.

{% tabs %}
{% tab title="instructions.txt" %}
```
Note to self:

Credentials for accessing the tenant. 
Hopefully no one can see this...

Tenant ID: c11b22d2-d015-47e0-bc0b-e6a0b1e25993
Application ID: ee767510-7041-4930-a672-1217ff9ff51a
Client Secret: pnh8Q~g~.gDOjPHNDNSGq7dFBUkjEMQ1I5HJydaQ
```
{% endtab %}
{% endtabs %}

We are given the `Tenant ID`, `Application ID`, and `Client Secret`. Upon searching these up, we find that we can use `azure cli` to login as the tenant-id using these values.

### Logging in to Azure Cloud

I wasn't sure how to login to Azure Powershell using these values, but I managed to login to azure cli (make sure to install azure cli if you do not have it)

<figure><img src="../../../.gitbook/assets/image (20) (3).png" alt=""><figcaption><p>az cli login</p></figcaption></figure>

I wanted to login to Azure Powershell as I am more familiar with the tools that Azure Powershell provides. So I grabbed a command from [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Cloud%20-%20Azure%20Pentest.md#get-tokens) to generate a token and login into Azure Powershell. I also grabbed [another command](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Cloud%20-%20Azure%20Pentest.md#use-tokens) that allows me to login to Azure Powershell using that token.

<figure><img src="../../../.gitbook/assets/image (8) (1).png" alt=""><figcaption><p>Generate Token</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (12) (2).png" alt=""><figcaption><p>Azure Powershell Login</p></figcaption></figure>

### Enumerate Storage Account

Remember when enumerating the cloud domain name using **cloud\_enum.py**, we found two storage accounts `lncctf2023` and `lncctf2023private`. Now, the private one seems suspicious, so we will look into that.

<figure><img src="../../../.gitbook/assets/image (5) (2).png" alt=""><figcaption><p>Storage Accounts</p></figcaption></figure>

Since we are logged in as the tenant, we can try to list the storage accounts we have access to. This can be done in `azure cli` by running the command `az storage account list`. This is the result:

<details>

<summary>Storage Accounts</summary>

```
[
  {
    "accessTier": "Hot",
    "allowBlobPublicAccess": true,
    "azureFilesIdentityBasedAuthentication": null,
    "blobRestoreStatus": null,
    "creationTime": "2023-04-14T10:21:08.212826+00:00",
    "customDomain": {
      "name": "www.lncctf2023.tk",
      "useSubDomainName": null
    },
    "enableHttpsTrafficOnly": false,
    "encryption": {
      "keySource": "Microsoft.Storage",
      "keyVaultProperties": null,
      "requireInfrastructureEncryption": null,
      "services": {
        "blob": {
          "enabled": true,
          "keyType": "Account",
          "lastEnabledTime": "2023-04-14T10:21:08.322256+00:00"
        },
        "file": {
          "enabled": true,
          "keyType": "Account",
          "lastEnabledTime": "2023-04-14T10:21:08.322256+00:00"
        },
        "queue": null,
        "table": null
      }
    },
    "failoverInProgress": null,
    "geoReplicationStats": null,
    "id": "/subscriptions/d7748706-f6cc-4e9d-a1f8-1fc802191456/resourceGroups/lncctf2023_cloudy_meatball_rg/providers/Microsoft.Storage/storageAccounts/lncctf2023",
    "identity": {
      "principalId": null,
      "tenantId": null
    },
    "isHnsEnabled": false,
    "kind": "StorageV2",
    "largeFileSharesState": null,
    "lastGeoFailoverTime": null,
    "location": "southeastasia",
    "minimumTlsVersion": "TLS1_2",
    "name": "lncctf2023",
    "networkRuleSet": {
      "bypass": "AzureServices",
      "defaultAction": "Allow",
      "ipRules": [],
      "virtualNetworkRules": []
    },
    "primaryEndpoints": {
      "blob": "https://lncctf2023.blob.core.windows.net/",
      "dfs": "https://lncctf2023.dfs.core.windows.net/",
      "file": "https://lncctf2023.file.core.windows.net/",
      "internetEndpoints": null,
      "microsoftEndpoints": null,
      "queue": "https://lncctf2023.queue.core.windows.net/",
      "table": "https://lncctf2023.table.core.windows.net/",
      "web": "https://lncctf2023.z23.web.core.windows.net/"
    },
    "primaryLocation": "southeastasia",
    "privateEndpointConnections": [],
    "provisioningState": "Succeeded",
    "resourceGroup": "lncctf2023_cloudy_meatball_rg",
    "routingPreference": null,
    "secondaryEndpoints": null,
    "secondaryLocation": null,
    "sku": {
      "name": "Standard_LRS",
      "tier": "Standard"
    },
    "statusOfPrimary": "available",
    "statusOfSecondary": null,
    "tags": {},
    "type": "Microsoft.Storage/storageAccounts"
  },
  {
    "accessTier": "Hot",
    "allowBlobPublicAccess": true,
    "azureFilesIdentityBasedAuthentication": null,
    "blobRestoreStatus": null,
    "creationTime": "2023-04-14T10:21:08.181567+00:00",
    "customDomain": null,
    "enableHttpsTrafficOnly": false,
    "encryption": {
      "keySource": "Microsoft.Storage",
      "keyVaultProperties": null,
      "requireInfrastructureEncryption": null,
      "services": {
        "blob": {
          "enabled": true,
          "keyType": "Account",
          "lastEnabledTime": "2023-04-14T10:21:08.290956+00:00"
        },
        "file": {
          "enabled": true,
          "keyType": "Account",
          "lastEnabledTime": "2023-04-14T10:21:08.290956+00:00"
        },
        "queue": null,
        "table": null
      }
    },
    "failoverInProgress": null,
    "geoReplicationStats": null,
    "id": "/subscriptions/d7748706-f6cc-4e9d-a1f8-1fc802191456/resourceGroups/lncctf2023_cloudy_meatball_rg/providers/Microsoft.Storage/storageAccounts/lncctf2023private",
    "identity": {
      "principalId": null,
      "tenantId": null
    },
    "isHnsEnabled": false,
    "kind": "StorageV2",
    "largeFileSharesState": null,
    "lastGeoFailoverTime": null,
    "location": "southeastasia",
    "minimumTlsVersion": "TLS1_2",
    "name": "lncctf2023private",
    "networkRuleSet": {
      "bypass": "AzureServices",
      "defaultAction": "Allow",
      "ipRules": [],
      "virtualNetworkRules": []
    },
    "primaryEndpoints": {
      "blob": "https://lncctf2023private.blob.core.windows.net/",
      "dfs": "https://lncctf2023private.dfs.core.windows.net/",
      "file": "https://lncctf2023private.file.core.windows.net/",
      "internetEndpoints": null,
      "microsoftEndpoints": null,
      "queue": "https://lncctf2023private.queue.core.windows.net/",
      "table": "https://lncctf2023private.table.core.windows.net/",
      "web": "https://lncctf2023private.z23.web.core.windows.net/"
    },
    "primaryLocation": "southeastasia",
    "privateEndpointConnections": [],
    "provisioningState": "Succeeded",
    "resourceGroup": "lncctf2023_cloudy_meatball_rg",
    "routingPreference": null,
    "secondaryEndpoints": null,
    "secondaryLocation": null,
    "sku": {
      "name": "Standard_LRS",
      "tier": "Standard"
    },
    "statusOfPrimary": "available",
    "statusOfSecondary": null,
    "tags": {},
    "type": "Microsoft.Storage/storageAccounts"
  }
]

```

</details>

Using this result, we need to get the name of the `storage account` and the `resource group`, which in this case is `lncctf2023private` and `lncctf2023_cloudy_meatball_rg` respectively.

Switching back to Azure Powershell, we can use this [portion](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Cloud%20-%20Azure%20Pentest.md#list-and-download-blobs) of PayloadAllTheThings once again, to list and grab the blobs.

<figure><img src="../../../.gitbook/assets/image (1) (4).png" alt=""><figcaption><p>Get Storage Account</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (19) (1).png" alt=""><figcaption><p>Get Storage Container</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (10) (3).png" alt=""><figcaption><p>Get Storage Blob</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (39).png" alt=""><figcaption><p>Download Blob and Get Flag</p></figcaption></figure>

