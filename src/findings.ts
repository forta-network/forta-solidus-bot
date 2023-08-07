import { Finding, FindingType, FindingSeverity, Label, EntityType } from "forta-agent";
import { utils } from "ethers";
import { ScamTokenResult, FalsePositiveEntry, Exploit } from "./types";

export function createScamTokenFinding(scamTokenResult: ScamTokenResult): Finding {
  const { chain_id, address, deployer_addr, name, symbol, created_at, exploits }: ScamTokenResult = scamTokenResult;
  const { id: exploit_id, name: exploit_name, types: exploit_type }: Exploit = exploits[0];
  const resultString: string = chain_id + address + deployer_addr + name + symbol + created_at;
  const uniqueKey: string = utils.keccak256(utils.toUtf8Bytes(resultString));

  return Finding.fromObject({
    name: `Scam token contract detected: ${name}`,
    description: exploit_name,
    alertId: "SCAM-TOKEN-NEW",
    severity: FindingSeverity.Critical,
    type: FindingType.Scam,
    uniqueKey,
    source: { chainSource: { chainId: Number(chain_id) } },
    addresses: [address, deployer_addr],
    protocol: name,
    metadata: {
      chain_id,
      deployer_addr,
      address,
      created_at,
      name,
      symbol,
      exploit_id: exploit_id.toString(),
      exploit_name,
      exploit_type,
    },
    labels: [
      Label.fromObject({
        entity: address,
        entityType: EntityType.Address,
        label: "Scam token contract",
        confidence: 0.99,
        remove: false,
        metadata: {
          chain_id,
          address,
          deployer_addr,
          created_at,
          name,
          symbol,
          exploit_id: exploit_id.toString(),
          exploit_name,
          exploit_type,
        },
      }),
      Label.fromObject({
        entity: deployer_addr,
        entityType: EntityType.Address,
        label: "Scam token contract deployer",
        confidence: 0.99,
        remove: false,
        metadata: {
          chain_id,
          address,
          deployer_addr,
          created_at,
          name,
          symbol,
          exploit_id: exploit_id.toString(),
          exploit_name,
          exploit_type,
        },
      }),
    ],
  });
}

export function createFalsePositiveFinding(
  falsePositiveEntry: FalsePositiveEntry,
  labelMetadata: { [key: string]: string }
): Finding {
  const {
    chain_id,
    address,
    deployer_addr,
    name,
    symbol,
    created_at,
    exploit_id,
    exploit_name,
    exploit_type,
  }: { [key: string]: string } = labelMetadata;
  const { contractName, contractAddress, deployerAddress, creationTransaction, chainId }: FalsePositiveEntry = falsePositiveEntry;
  const resultString: string = contractName + contractAddress + deployerAddress + creationTransaction + chainId;
  const uniqueKey: string = utils.keccak256(utils.toUtf8Bytes(resultString));

  return Finding.fromObject({
    name: `False positive scam token contract, and its deployer, previously incorrectly labeled: ${falsePositiveEntry["contractName"]}`,
    description: `Scam token detector previously labeled ${falsePositiveEntry["contractName"]} contract at ${falsePositiveEntry["contractAddress"]}, and its deployer ${falsePositiveEntry["deployerAddress"]}, a scam token`,
    alertId: "SCAM-TOKEN-FALSE-POSITIVE",
    severity: FindingSeverity.Info,
    type: FindingType.Info,
    uniqueKey,
    source: { chainSource: { chainId: Number(chain_id) } },
    metadata: {},
    labels: [
      Label.fromObject({
        entity: falsePositiveEntry["contractAddress"],
        entityType: EntityType.Address,
        label: "Scam token contract",
        confidence: 0.99,
        remove: true,
        metadata: {
          chain_id,
          address,
          deployer_addr,
          created_at,
          name,
          symbol,
          exploit_id,
          exploit_name,
          exploit_type,
        },
      }),
      Label.fromObject({
        entity: falsePositiveEntry["deployerAddress"],
        entityType: EntityType.Address,
        label: "Scam token contract deployer",
        confidence: 0.99,
        remove: true,
        metadata: {
          chain_id,
          address,
          deployer_addr,
          created_at,
          name,
          symbol,
          exploit_id,
          exploit_name,
          exploit_type,
        },
      }),
    ],
  });
}
