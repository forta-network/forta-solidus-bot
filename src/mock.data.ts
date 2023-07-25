import { Label, EntityType } from "forta-agent";
import { createAddress } from "forta-agent-tools";
import { RugPullResult, RugPullPayload } from "./types";

function createSingleRugPullResult(identifier: number): RugPullResult {
  const rugPullResult: RugPullResult = {
    chain_id: "56",
    address: createAddress(`0x${identifier}0`),
    deployer_addr: createAddress(`0x${identifier}${identifier}`),
    name: `mock${identifier}`,
    symbol: `M${identifier}`,
    created_at: `2023-07-17T20:10:00.0${identifier}Z`,
    exploits: [
      {
        id: identifier,
        name: `Exploit name 0${identifier}`,
        types: `Exploit type 0${identifier}`,
      },
    ],
  };

  return rugPullResult;
}

export function createMockRugPullResults(amount: number): RugPullPayload {
  const rugPullPayload: RugPullPayload = {
    message: "OK",
    total: amount,
    result: [],
  };

  for (let i = 1; i <= amount; i++) {
    rugPullPayload["result"].push(createSingleRugPullResult(i));
  }

  return rugPullPayload;
}

export function createFetchedLabels(
  chainId: string,
  contractAddress: string,
  deployerAddress: string,
  creationTime: string,
  contractName: string,
  tokenSymbol: string,
  exploitId: string,
  exploitName: string,
  exploitType: string,
  contractLabel: string,
  deployerLabel: string
): Label[] {
  const labels: Label[] = [
    {
      entity: contractAddress,
      entityType: EntityType.Address,
      label: contractLabel,
      confidence: 0.99,
      remove: false,
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
    },
    {
      entity: deployerAddress,
      entityType: EntityType.Address,
      label: deployerLabel,
      confidence: 0.99,
      remove: false,
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
    },
  ];

  return labels;
}
