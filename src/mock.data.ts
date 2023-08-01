import { Label, EntityType } from "forta-agent";
import { createAddress } from "forta-agent-tools";
import { ScamTokenResult } from "./types";

function createSingleScamTokenResult(identifier: number): ScamTokenResult {
  const ScamTokenResult: ScamTokenResult = {
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

  return ScamTokenResult;
}

export function createMockScamTokenResults(amount: number): ScamTokenResult[] {
  const ScamTokenPayload: ScamTokenResult[] = [];

  for (let i = 1; i <= amount; i++) {
    ScamTokenPayload.push(createSingleScamTokenResult(i));
  }

  return ScamTokenPayload;
}

export function createFetchedLabels(
  chain_id: string,
  address: string,
  deployer_addr: string,
  created_at: string,
  name: string,
  symbol: string,
  exploit_id: string,
  exploit_name: string,
  exploit_type: string,
  contract_label: string,
  deployer_label: string
): Label[] {
  const labels: Label[] = [
    {
      entity: address,
      entityType: EntityType.Address,
      label: contract_label,
      confidence: 0.99,
      remove: false,
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
    },
    {
      entity: deployer_addr,
      entityType: EntityType.Address,
      label: deployer_label,
      confidence: 0.99,
      remove: false,
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
    },
  ];

  return labels;
}

/*
metadata: {
  ,
  ,
  ,
  ,
  ,
  ,
  ,
  ,
}
*/
