import { Finding, FindingType, FindingSeverity, Label, EntityType } from "forta-agent";
import { utils } from "ethers";
import { RugPullResult, FalsePositiveEntry } from "./types";

export function createRugPullFinding(rugPullResult: RugPullResult): Finding {
  const { chain_id, address, deployer_addr, name, symbol, created_at }: RugPullResult = rugPullResult;
  const resultString: string = chain_id + address + deployer_addr + name + symbol + created_at;
  const uniqueKey: string = utils.keccak256(utils.toUtf8Bytes(resultString));

  return Finding.fromObject({
    name: `Rug pull contract detected: ${rugPullResult["name"]}`,
    description: rugPullResult["exploits"][0]["name"],
    alertId: "SOLIDUS-RUG-PULL",
    severity: FindingSeverity.Critical,
    type: FindingType.Scam,
    // uniqueKey,
    // source: { chainSource: { chainId: Number(rugPullResult["chain_id"]) } },

    metadata: {
      chainId: rugPullResult["chain_id"],
      deployerAddress: rugPullResult["deployer_addr"],
      createdAddress: rugPullResult["address"],
      creationTime: rugPullResult["created_at"],
      contractName: rugPullResult["name"],
      tokenSymbol: rugPullResult["symbol"],
      exploitId: rugPullResult["exploits"][0]["id"].toString(),
      exploitName: rugPullResult["exploits"][0]["name"],
      exploitType: rugPullResult["exploits"][0]["types"],
    },
    labels: [
      Label.fromObject({
        entity: rugPullResult["address"],
        entityType: EntityType.Address,
        label: "Rug pull contract",
        confidence: 0.99,
        remove: false,
        metadata: {
          chainId: rugPullResult["chain_id"],
          contractAddress: rugPullResult["address"],
          deployerAddress: rugPullResult["deployer_addr"],
          creationTime: rugPullResult["created_at"],
          contractName: rugPullResult["name"],
          tokenSymbol: rugPullResult["symbol"],
          exploitId: rugPullResult["exploits"][0]["id"].toString(),
          exploitName: rugPullResult["exploits"][0]["name"],
          exploitType: rugPullResult["exploits"][0]["types"],
        },
      }),
      Label.fromObject({
        entity: rugPullResult["deployer_addr"],
        entityType: EntityType.Address,
        label: "Rug pull contract deployer",
        confidence: 0.99,
        remove: false,
        metadata: {
          chainId: rugPullResult["chain_id"],
          contractAddress: rugPullResult["address"],
          deployerAddress: rugPullResult["deployer_addr"],
          creationTime: rugPullResult["created_at"],
          contractName: rugPullResult["name"],
          tokenSymbol: rugPullResult["symbol"],
          exploitId: rugPullResult["exploits"][0]["id"].toString(),
          exploitName: rugPullResult["exploits"][0]["name"],
          exploitType: rugPullResult["exploits"][0]["types"],
        },
      }),
    ],
  });
}

export function createFalsePositiveFinding(
  falsePositiveEntry: FalsePositiveEntry,
  labelMetadata: { [key: string]: string }
): Finding {
  return Finding.fromObject({
    name: `False positive rug pull contract, and its deployer, previously incorrectly labeled: ${falsePositiveEntry["contractName"]}`,
    description: `Rug pull detector previously labeled ${falsePositiveEntry["contractName"]} contract at ${falsePositiveEntry["contractAddress"]}, and its deployer ${falsePositiveEntry["deployerAddress"]}, a rug pull`,
    alertId: "SOLIDUS-RUG-PULL-FALSE-POSITIVE",
    severity: FindingSeverity.Info,
    type: FindingType.Info,
    metadata: {},
    labels: [
      Label.fromObject({
        entity: falsePositiveEntry["contractAddress"],
        entityType: EntityType.Address,
        label: "Rug pull contract",
        confidence: 0.99,
        remove: true,
        metadata: {
          chainId: labelMetadata.chainId,
          contractAddress: labelMetadata.contractAddress,
          deployerAddress: labelMetadata.deployerAddress,
          creationTime: labelMetadata.creationTime,
          contractName: labelMetadata.contractName,
          tokenSymbol: labelMetadata.tokenSymbol,
          exploitId: labelMetadata.exploitId,
          exploitName: labelMetadata.exploitName,
          exploitType: labelMetadata.exploitType,
        },
      }),
      Label.fromObject({
        entity: falsePositiveEntry["deployerAddress"],
        entityType: EntityType.Address,
        label: "Rug pull contract deployer",
        confidence: 0.99,
        remove: true,
        metadata: {
          chainId: labelMetadata.chainId,
          contractAddress: labelMetadata.contractAddress,
          deployerAddress: labelMetadata.deployerAddress,
          creationTime: labelMetadata.creationTime,
          contractName: labelMetadata.contractName,
          tokenSymbol: labelMetadata.tokenSymbol,
          exploitId: labelMetadata.exploitId,
          exploitName: labelMetadata.exploitName,
          exploitType: labelMetadata.exploitType,
        },
      }),
    ],
  });
}
