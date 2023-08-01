# TokenSniffer Scam Token Detector

## About the Developer

Solidus Labs is the category-definer for crypto-native market integrity solutions - trade surveillance, transaction monitoring, and threat intelligence. More information about Solidus is contained at the bottom of the documentation. 

## Description

This bot detects scam tokens by comparing the smart contract source code and bytecode against a database of thousands of known scam patterns using the [TokenSniffer API](https://tokensniffer.com/TokenSnifferAPI).  It supports the same scam detection functionality as the [TokenSniffer web site](https://tokensniffer.com).

## How it Works

The bot listens to the websocket stream of newly detected scam tokens from the [TokenSniffer API](https://tokensniffer.com/TokenSnifferAPI).  As new token smart contracts are deployed on-chain and/or source code is verified on the respective block explorer web site, TokenSniffer searches the contract source code against a database of known scam code patterns much in the same way a virus scanner searches executable programs for known virus code patterns.  For tokens without verified source code available a token may be alerted as a scam based on bytecode similarity to known scam contracts.  The bot emits an alert the contains information about the token and the type(s) of scam detected.

## Supported Standards

- ERC-20

## Supported Chains

- Ethereum (1)
- BSC (56)
- Polygon (137)
- Arbitrum (42161)
- Optimism (10)
- Fantom (250)
- Avalanche (43114)
- Cronos (25)
- Gnosis (100)
- KCC (321)
- Oasis (42262)
- Harmony (1666600000)


## Alerts

- SCAM-TOKEN-NEW

  - Fired when a new token has been flagged as a scam by the code scanner
  - Severity is always set to "Critical"
  - Type is always set to "Scam"
  - `uniqueKey`: A unique hash derived from `chain_id`, `address`, `deployer_addr`, `name`, `symbol`, and `created_at`
  - `addresses`: A list containing the scam token contract address and contract deployer address
  - `protocol`: The name of the token as required by ERC-20
  - `source`: The blockchain identifier for the token
  - Metadata:
    - `chain_id` - The blockchain identifier for the token
    - `address` - The contract address for the token
    - `deployer_addr` - The address that deployed the token contract
    - `name` - The name of the token as required by ERC-20
    - `symbol` - The symbol of the token as required by ERC-20
    - `created_at` - The datetime that the token contract was deployed on chain
    - `exploit_id` - An integer identifier for the code rule that was triggered
    - `exploit_name` - A string description of the code rule that was triggered
    - `exploit_type` - A comma-separated list of strings describing the categories of the scam code detected. Possible values include:
      - `honeypot`
      - `hidden mint`
      - `hidden fee modifier`
      - `hidden transfer`
      - `hidden balance modifier`
      - `hidden max transaction amount modifier`
      - `LP block`
      - `blocklist/allowlist`
      - `fake ownership renounce`
      - `mint to multiple wallets during creation`
      - `restricted selling`
      - `external contract`

- SCAM-TOKEN-FALSE-POSITIVE

  - Fired when a false positive was identified manually for a token contract and its deployer
    - Removes the previous label for this entity
  - Severity is always set to "info"
  - Type is always set to "info"
  - `uniqueKey`: A unique hash specific to this alert. Derived from `chain_id`, `address`, `deployer_addr`, `name`, `symbol` of the previously generated labels.
  - `source`: The blockchain identifier for the token
      

## Labels

- Scam Token Contract
  - `entityType`: EntityType.Address
  - `label`: "Scam token contract"
  - `entity`: Scam token address
  - `confidence`: 0.99
  - `metadata`:
    - `chain_id` - The blockchain identifier for the token
    - `address` - The contract address for the token
    - `deployer_addr` - The address that deployed the token contract
    - `name` - The name of the token as required by ERC-20
    - `symbol` - The symbol of the token as required by ERC-20
    - `created_at` - The datetime that the token contract was deployed on chain
    - `exploit_id` - An integer identifier for the code rule that was triggered
    - `exploit_name` - A string description of the code rule that was triggered
    - `exploit_type` - A comma-separated list of strings describing the categories of the scam code detected.

- Scam Token Contract Deployer
  - `entityType`: EntityType.Address
  - `label`: "Scam token contract deployer"
  - `entity`: Scam token deployer address
  - `confidence`: 0.99
  - `metadata`:
    - `chain_id` - The blockchain identifier for the token
    - `address` - The contract address for the token
    - `deployer_addr` - The address that deployed the token contract
    - `name` - The name of the token as required by ERC-20
    - `symbol` - The symbol of the token as required by ERC-20
    - `created_at` - The datetime that the token contract was deployed on chain
    - `exploit_id` - An integer identifier for the code rule that was triggered
    - `exploit_name` - A string description of the code rule that was triggered
    - `exploit_type` - A comma-separated list of strings describing the categories of the scam code detected.

## Test Data

Test suite in `./src/agent.spec.ts`.

## Data Sources

Smart contract source code provided by:
- Ethereum:  Etherscan (https://etherscan.io/)
- BSC:  BSCScan (https://bscscan.com/)
- Polygon:  PolygonScan (https://polygonscan.com/)
- Arbitrum:  ArbiScan (https://arbiscan.io/)
- Optimism:  Optimism Explorer (https://optimistic.etherscan.io/)
- Fantom:  FTMScan (https://ftmscan.com/)
- Avalanche:  SnowTrace (https://snowtrace.io/)
- Cronos:  Cronos Explorer (https://cronos.crypto.org/explorer)
- Gnosis:  Blockscout (https://blockscout.com)
- KCC:  KCC Explorer (https://explorer.kcc.io/)
- Oasis:  Oasis Explorer (https://explorer.emerald.oasis.dev')
- Harmony:  Harmony Explorer (https://explorer.harmony.one)

## License

The bot is released under the [Forta Bot License](./LICENSE).

## About the Developer

Solidus Labs is the category-definer for crypto-native market integrity solutions - trade surveillance, transaction monitoring, and threat intelligence. Our mission is to enable safe crypto trading throughout the investment journey across all centralized and DeFi markets. As the founder of industry-leading initiatives like the Crypto Market Integrity Coalition and DACOM Summit, and in everything we do, Solidus is deeply committed to ushering in the financial markets of tomorrow.

Solidus Labs has been an active member of the Forta community from the beginning. We joined the first community call in Fall 2021 and have provided regular feedback since then. We are also an active user of the Forta Network. 