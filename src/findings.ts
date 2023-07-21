import { Finding, FindingType, FindingSeverity, Label, EntityType } from "forta-agent";
import { RugPullResult, FalsePositiveInfo } from "./types";

export function createRugPullFinding(rugPullResult: RugPullResult): Finding {
  return Finding.fromObject({
    name: `Rug pull contract detected: ${rugPullResult["name"]}`,
    description: rugPullResult["exploits"][0]["name"],
    alertId: "SOLIDUS-RUG-PULL",
    severity: FindingSeverity.Critical,
    type: FindingType.Scam,
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

export function createContractFalsePositiveFinding(
  falsePositiveEntry: FalsePositiveInfo,
  chainId: string,
  contractAddress: string,
  deployerAddress: string,
  creationTime: string,
  contractName: string,
  tokenSymbol: string,
  exploitId: string,
  exploitName: string,
  exploitType: string
): Finding {
  return Finding.fromObject({
    name: `False positive rug pull contract previously incorrectly labeled: ${falsePositiveEntry["contractName"]}`,
    description: `Rug pull detector previously labeled ${falsePositiveEntry["contractName"]} contract at ${falsePositiveEntry["contractAddress"]} a rug pull`,
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
          chainId,
          contractAddress,
          deployerAddress,
          creationTime,
          contractName,
          tokenSymbol,
          exploitId,
          exploitName,
          exploitType,
        },
      }),
    ],
  });
}

export function createDeployerFalsePositiveFinding(
  falsePositiveEntry: FalsePositiveInfo,
  chainId: string,
  contractAddress: string,
  deployerAddress: string,
  creationTime: string,
  contractName: string,
  tokenSymbol: string,
  exploitId: string,
  exploitName: string,
  exploitType: string
): Finding {
  return Finding.fromObject({
    name: "False positive rug pull contract deployer previously incorrectly labeled",
    description: `Rug pull detector previously labeled ${falsePositiveEntry["deployerAddress"]} a rug pull deployer`,
    alertId: "SOLIDUS-RUG-PULL-FALSE-POSITIVE",
    severity: FindingSeverity.Info,
    type: FindingType.Info,
    metadata: {},
    labels: [
      Label.fromObject({
        entity: falsePositiveEntry["deployerAddress"],
        entityType: EntityType.Address,
        label: "Rug pull contract deployer",
        confidence: 0.99,
        remove: true,
        metadata: {
          chainId,
          contractAddress,
          deployerAddress,
          creationTime,
          contractName,
          tokenSymbol,
          exploitId,
          exploitName,
          exploitType,
        },
      }),
    ],
  });
}
