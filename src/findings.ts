import { Finding, FindingType, FindingSeverity, Label, EntityType } from "forta-agent";
import { utils } from "ethers";
import { RugPullResult, FalsePositiveEntry, Exploit } from "./types";

export function createRugPullFinding(rugPullResult: RugPullResult): Finding {
  const {
    chain_id: chainId,
    address: contractAddress,
    deployer_addr: deployerAddress,
    name: contractName,
    symbol: tokenSymbol,
    created_at: creationTime,
    exploits,
  }: RugPullResult = rugPullResult;
  const { id: exploitId, name: exploitName, types: exploitType }: Exploit = exploits[0];
  const resultString: string = chainId + contractAddress + deployerAddress + contractName + tokenSymbol + creationTime;
  const uniqueKey: string = utils.keccak256(utils.toUtf8Bytes(resultString));

  return Finding.fromObject({
    name: `Rug pull contract detected: ${contractName}`,
    description: exploitName,
    alertId: "SOLIDUS-RUG-PULL",
    severity: FindingSeverity.Critical,
    type: FindingType.Scam,
    // uniqueKey,
    // source: { chainSource: { chainId: Number(chainId) } },
    metadata: {
      chainId,
      deployerAddress,
      contractAddress,
      creationTime,
      contractName,
      tokenSymbol,
      exploitId: exploitId.toString(),
      exploitName,
      exploitType,
    },
    labels: [
      Label.fromObject({
        entity: contractAddress,
        entityType: EntityType.Address,
        label: "Rug pull contract",
        confidence: 0.99,
        remove: false,
        metadata: {
          chainId,
          contractAddress,
          deployerAddress,
          creationTime,
          contractName,
          tokenSymbol,
          exploitId: exploitId.toString(),
          exploitName,
          exploitType,
        },
      }),
      Label.fromObject({
        entity: deployerAddress,
        entityType: EntityType.Address,
        label: "Rug pull contract deployer",
        confidence: 0.99,
        remove: false,
        metadata: {
          chainId,
          contractAddress,
          deployerAddress,
          creationTime,
          contractName,
          tokenSymbol,
          exploitId: exploitId.toString(),
          exploitName,
          exploitType,
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
    chainId,
    contractAddress,
    deployerAddress,
    contractName,
    tokenSymbol,
    creationTime,
    exploitId,
    exploitName,
    exploitType,
  }: { [key: string]: string } = labelMetadata;
  // Exclude `creationTime` from `resultString` to
  // not create exact same `uniqueKey` as other Finding
  const resultString: string = chainId + contractAddress + deployerAddress + contractName + tokenSymbol;
  const uniqueKey: string = utils.keccak256(utils.toUtf8Bytes(resultString));

  return Finding.fromObject({
    name: `False positive rug pull contract, and its deployer, previously incorrectly labeled: ${falsePositiveEntry["contractName"]}`,
    description: `Rug pull detector previously labeled ${falsePositiveEntry["contractName"]} contract at ${falsePositiveEntry["contractAddress"]}, and its deployer ${falsePositiveEntry["deployerAddress"]}, a rug pull`,
    alertId: "SOLIDUS-RUG-PULL-FALSE-POSITIVE",
    severity: FindingSeverity.Info,
    type: FindingType.Info,
    // uniqueKey,
    // source: { chainSource: { chainId: Number(chainId) } },
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
