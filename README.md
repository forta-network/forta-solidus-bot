# Token Sniffer Rug Pull Detector Bot

## Description

This bot is an extension of Token Sniffer, the first and most-used token security platform, powered by Solidus Labs. Token Sniffer’s smart contract scanner analyzes token contract code and functionality, testing for malicious patterns to assess whether or not a token is a hard rug pull. It provides intelligence on both the token and the token’s creator. This bot covers seven typologies of hard rug pulls across twelve different EVM chains. 

## Supported Chains
> Note: Bot monitors mainnet Ethereum, but via the Token Sniffer data source, its monitorsing of rug pull activity is extended to the chains below.
- Ethereum
- Optimism
- BNB Smart Chain
- Polygon
- Fantom
- Arbitrum
- Avalanche
- Gnosis (xDAI)
- Harmony
- KuCoin Community Chain (KCC)
- Cronos
- Oasis


## Alerts

- SOLIDUS-RUG-PULL

  - Fired when Token Sniffer has identified a rug pull contract
  - Severity is always set to "critical"
  - Type is always set to "scam"
  - Metadata:
    - `chainId` - identifier of which chain the contract was deployed
    - `deployerAddress` - address of contract deployer account
    - `createdAddress` - address of created rug pull contract
    - `creationTime` - contract creation time
    - `contractName` - contract name
    - `tokenSymbol` - symbol for contract's token
    - `exploitId` - exploit's identifier
    - `exploitName` - name of exploit
    - `exploitType` - type of exploit
  - Labels:
    - Label 1:
      - `entity`: Created rug pull contract address
      - `entityType`: The type of the entity, always set to "Address"
      - `label`: The type of the label, always set to "Rug pull contract"
      - `confidence`: The confidence level of the contract being a rug pull, always set to "0.99"
      - `metadata`:
        - `chainId` - identifier of which chain the contract was deployed
        - `deployerAddress` - address of contract deployer account
        - `createdAddress` - address of created rug pull contract
        - `creationTime` - contract creation time
        - `contractName` - contract name
        - `tokenSymbol` - symbol for contract's token
        - `exploitId` - exploit's identifier
        - `exploitName` - name of exploit
        - `exploitType` - type of exploit
    - Label 2:
      - `entity`: Deployer of rug pull contract address
      - `entityType`: The type of the entity, always set to "Address"
      - `label`: The type of the label, always set to "Rug pull contract deployer"
      - `confidence`: The confidence level of the contract being a rug pull, always set to "0.99"
      - `metadata`:
        - `chainId` - identifier of which chain the contract was deployed
        - `deployerAddress` - address of contract deployer account
        - `createdAddress` - address of created rug pull contract
        - `creationTime` - contract creation time
        - `contractName` - contract name
        - `tokenSymbol` - symbol for contract's token
        - `exploitId` - exploit's identifier
        - `exploitName` - name of exploit
        - `exploitType` - type of exploit

- SOLIDUS-RUG-PULL-FALSE-POSITIVE

  - Fired when a false positive was identified for a contract and its deployer
    - Removes the previous label for this entity
  - Severity is always set to "info"
  - Type is always set to "info"
  - Labels:
    - Label 1:
      - `entity`: Contract previously declared a rug pull contract
      - `entityType`: The type of the entity, always set to "Address"
      - `label`: The type of the label, always set to "Rug pull contract"
      - `confidence`: The confidence level of the contract being a rug pull, always set to "0.99",
      - `remove`: Set to `true` to remove previously emitted label for this entity 
      - `metadata`:
        - `chainId` - identifier of which chain the contract was deployed
        - `deployerAddress` - address of contract deployer account
        - `createdAddress` - address of created rug pull contract
        - `creationTime` - contract creation time
        - `contractName` - contract name
        - `tokenSymbol` - symbol for contract's token
        - `exploitId` - exploit's identifier
        - `exploitName` - name of exploit
        - `exploitType` - type of exploit
    - Label 2:
      - `entity`: Account previously declared a rug pull contract deployer
      - `entityType`: The type of the entity, always set to "Address"
      - `label`: The type of the label, always set to "Rug pull contract deployer"
      - `confidence`: The confidence level of the contract being a rug pull, always set to "0.99",
      - `remove`: Set to `true` to remove previously emitted label for this entity 
      - `metadata`:
        - `chainId` - identifier of which chain the contract was deployed
        - `deployerAddress` - address of contract deployer account
        - `createdAddress` - address of created rug pull contract
        - `creationTime` - contract creation time
        - `contractName` - contract name
        - `tokenSymbol` - symbol for contract's token
        - `exploitId` - exploit's identifier
        - `exploitName` - name of exploit
        - `exploitType` - type of exploit

## Test Data

Test suite in `./src/agent.spec.ts`. Because this bot depends on an off-chain data source, it cannot be tested with specific transanctions nor blocks.