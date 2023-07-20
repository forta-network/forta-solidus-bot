import {
    Finding,
    FindingType,
    FindingSeverity,
    Label,
    EntityType
} from "forta-agent";

export function createFinding(entry: any): Finding {
    return Finding.fromObject({
        name: `Rug pull contract detected: ${entry["name"]}`,
        description: entry["exploits"][0]["name"],
        alertId: "SOLIDUS-RUG-PULL",
        severity: FindingSeverity.Critical,
        type: FindingType.Scam,
        metadata: {
          chainId: entry["chain_id"],
          deployerAddress: entry["deployer_addr"],
          createdAddress: entry["address"],
          creationTime: entry["created_at"],
          contractName: entry["name"],
          tokenSymbol: entry["symbol"],
          exploitName: entry["exploits"][0]["name"],
          exploitType: entry["exploits"][0]["type"]
        },
        labels: [
          Label.fromObject({
            entity: entry["address"],
            entityType: EntityType.Address,
            label: "Rug pull contract",
            confidence: 0.99,
            remove: false
          }),
          Label.fromObject({
            entity: entry["deployer_addr"],
            entityType: EntityType.Address,
            label: "Rug pull contract deployer",
            confidence: 0.99,
            remove: false
          }),
        ]
    });
};

export function createFalsePositiveFinding(entry: any): Finding {
  return Finding.fromObject({
    name: `False positive rug pull contract previously incorrectly labeled: ${entry[0]}`,
    description: `Rug pull detector previously labeled ${entry[0]} contract at ${entry[1]["contractAddress"]} a rug pull`,
    alertId: "SOLIDUS-RUG-PULL-FALSE-POSITIVE",
    severity: FindingSeverity.Info,
    type: FindingType.Info,
    metadata: {},
    labels: [
      Label.fromObject({
        entity: entry[1]["contractAddress"],
        entityType: EntityType.Address,
        label: "Rug pull contract",
        confidence: 0.99,
        remove: true
      }),
      Label.fromObject({
        entity: entry[1]["deployerAddress"],
        entityType: EntityType.Address,
        label: "Rug pull contract deployer",
        confidence: 0.99,
        remove: true
      }),
    ]
  });
}